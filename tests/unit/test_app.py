import asyncio
import logging

import pytest

from waton.app.app import App
from waton.app.context import Context
from waton.app.middleware import MiddlewarePipeline
from waton.app.router import Router
from waton.core.entities import Message
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import wa_pb2


def _run(coro):
    return asyncio.run(coro)


def test_router_dispatches_matching_handlers() -> None:
    async def _case() -> None:
        router = Router()
        calls: list[str] = []

        @router.message()
        async def h1(ctx):
            calls.append("h1")

        @router.message(lambda ctx: ctx.text == "ok")
        async def h2(ctx):
            calls.append("h2")

        ctx = Context(message=Message(id="1", from_jid="a@s.whatsapp.net", text="ok"), app=None)  # type: ignore[arg-type]
        await router.dispatch(ctx)
        assert calls == ["h1", "h2"]

    _run(_case())


def test_middleware_pipeline_order() -> None:
    async def _case() -> None:
        pipe = MiddlewarePipeline()
        calls: list[str] = []

        async def mw1(ctx, nxt):
            calls.append("mw1_before")
            await nxt()
            calls.append("mw1_after")

        async def mw2(ctx, nxt):
            calls.append("mw2_before")
            await nxt()
            calls.append("mw2_after")

        async def handler(ctx):
            calls.append("handler")

        pipe.add(mw1)
        pipe.add(mw2)

        ctx = Context(message=Message(id="1", from_jid="a@s.whatsapp.net"), app=None)  # type: ignore[arg-type]
        await pipe.run(ctx, handler)
        assert calls == ["mw1_before", "mw2_before", "handler", "mw2_after", "mw1_after"]

    _run(_case())


def test_app_dispatches_command_handler() -> None:
    async def _case() -> None:
        app = App(storage_path=":memory:")
        seen: list[str] = []

        @app.command("!ping")
        async def ping(ctx):
            seen.append(ctx.text or "")

        msg = wa_pb2.Message()
        msg.conversation = "!ping hello"
        node = BinaryNode(
            tag="message",
            attrs={"id": "m1", "from": "123@s.whatsapp.net", "type": "text"},
            content=msg.SerializeToString(),
        )
        await app._dispatch_message(node)
        assert seen == ["!ping hello"]
        await app.media.http.aclose()

    _run(_case())


def test_app_exposes_community_and_newsletter_clients() -> None:
    app = App(storage_path=":memory:")
    assert app.communities is not None
    assert app.newsletter is not None
    _run(app.media.http.aclose())


def test_app_dispatch_falls_back_when_message_parse_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        app = App(storage_path=":memory:")
        seen: list[tuple[str, str]] = []

        @app.message()
        async def on_message(ctx: Context) -> None:
            seen.append((ctx.message.from_jid, ctx.message.message_type))

        async def _raise_parse_error(node: BinaryNode, client: object) -> object:
            del node, client
            raise ValueError("broken parser")

        monkeypatch.setattr("waton.app.app.process_incoming_message", _raise_parse_error)

        await app._dispatch_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m-fallback", "from": "628111111111@s.whatsapp.net", "type": "text"},
                content=b"broken",
            )
        )

        assert seen == [("628111111111@s.whatsapp.net", "text")]
        await app.media.http.aclose()

    _run(_case())


def test_app_dispatch_fallback_keeps_from_jid_as_sender_when_participant_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _case() -> None:
        app = App(storage_path=":memory:")
        seen: list[tuple[str, str, str | None]] = []

        @app.message()
        async def on_message(ctx: Context) -> None:
            seen.append((ctx.message.from_jid, ctx.message.message_type, ctx.message.participant))

        async def _raise_parse_error(node: BinaryNode, client: object) -> object:
            del node, client
            raise ValueError("broken parser")

        monkeypatch.setattr("waton.app.app.process_incoming_message", _raise_parse_error)

        await app._dispatch_message(
            BinaryNode(
                tag="message",
                attrs={
                    "id": "m-fallback-participant",
                    "from": "120363999999999999@g.us",
                    "participant": "628111111111@s.whatsapp.net",
                    "type": "text",
                },
                content=b"broken",
            )
        )

        assert seen == [("120363999999999999@g.us", "text", "628111111111@s.whatsapp.net")]
        await app.media.http.aclose()

    _run(_case())


def test_app_dispatch_trace_logs_include_correlation_success_path(caplog: pytest.LogCaptureFixture) -> None:
    async def _case() -> None:
        caplog.set_level(logging.DEBUG, logger="waton.app.app")
        caplog.set_level(logging.DEBUG, logger="waton.app.middleware")
        caplog.set_level(logging.DEBUG, logger="waton.app.router")

        app = App(storage_path=":memory:")
        seen: list[str] = []

        async def passthrough(_ctx: Context, nxt) -> None:
            await nxt()

        app.use(passthrough)

        @app.command("!ping")
        async def ping(ctx: Context) -> None:
            seen.append(ctx.text or "")

        msg = wa_pb2.Message()
        msg.conversation = "!ping tracing"
        node = BinaryNode(
            tag="message",
            attrs={"id": "m-trace", "from": "123@s.whatsapp.net", "type": "text"},
            content=msg.SerializeToString(),
        )
        await app._dispatch_message(node)

        assert seen == ["!ping tracing"]

        trace_records = [record for record in caplog.records if getattr(record, "trace_id", None)]
        assert trace_records
        assert {record.trace_id for record in trace_records} == {trace_records[0].trace_id}

        stages = {getattr(record, "stage", None) for record in trace_records}
        assert "dispatch_ingress" in stages
        assert "dispatch_parse_success" in stages
        assert "middleware_enter" in stages
        assert "middleware_exit" in stages
        assert "route_match" in stages
        assert "dispatch_complete" in stages

        message_ids = {getattr(record, "message_id", None) for record in trace_records}
        assert message_ids == {"m-trace"}

        await app.media.http.aclose()

    _run(_case())


def test_app_dispatch_trace_logs_include_correlation_fallback_path(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _case() -> None:
        caplog.set_level(logging.DEBUG, logger="waton.app.app")
        caplog.set_level(logging.DEBUG, logger="waton.app.middleware")
        caplog.set_level(logging.DEBUG, logger="waton.app.router")

        app = App(storage_path=":memory:")

        @app.message()
        async def on_message(ctx: Context) -> None:
            assert ctx.message.id == "m-fallback-trace"

        async def _raise_parse_error(node: BinaryNode, client: object) -> object:
            del node, client
            raise ValueError("broken parser")

        monkeypatch.setattr("waton.app.app.process_incoming_message", _raise_parse_error)

        await app._dispatch_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m-fallback-trace", "from": "628111111111@s.whatsapp.net", "type": "text"},
                content=b"broken",
            )
        )

        fallback_records = [
            record
            for record in caplog.records
            if getattr(record, "stage", None) == "dispatch_parse_fallback"
        ]
        assert len(fallback_records) == 1
        fallback_record = fallback_records[0]
        assert fallback_record.trace_id
        assert fallback_record.message_id == "m-fallback-trace"
        assert fallback_record.from_jid == "628111111111@s.whatsapp.net"

        await app.media.http.aclose()

    _run(_case())


def test_app_dispatch_context_carries_trace_id_to_handlers() -> None:
    async def _case() -> None:
        app = App(storage_path=":memory:")
        seen: list[str] = []

        @app.command("!ping")
        async def ping(ctx: Context) -> None:
            seen.append(ctx.trace_id)

        msg = wa_pb2.Message()
        msg.conversation = "!ping ctx trace"
        node = BinaryNode(
            tag="message",
            attrs={"id": "m-trace-context", "from": "123@s.whatsapp.net", "type": "text"},
            content=msg.SerializeToString(),
        )
        await app._dispatch_message(node)

        assert len(seen) == 1
        assert isinstance(seen[0], str)
        assert seen[0]

        await app.media.http.aclose()

    _run(_case())


def test_app_dispatch_trace_logs_use_stable_ingress_message_id(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _case() -> None:
        caplog.set_level(logging.DEBUG, logger="waton.app.app")
        caplog.set_level(logging.DEBUG, logger="waton.app.middleware")
        caplog.set_level(logging.DEBUG, logger="waton.app.router")

        app = App(storage_path=":memory:")

        class _Parsed:
            id = "parsed-id"
            from_jid = "parsed@s.whatsapp.net"
            participant = None
            text = "ok"
            media_url = None
            reaction = None
            reaction_target_id = None
            destination_jid = None
            protocol_type = None
            protocol_code = None
            target_message_id = None
            edited_text = None
            ephemeral_expiration = None
            history_sync_type = None
            app_state_key_ids: list[str] = []
            encrypted_reaction = None
            poll_update = None
            event_response = None
            content_type = None
            content: dict[str, object] = {}
            message_secret_b64 = None
            message_type = "text"

        async def _parsed(*_args: object, **_kwargs: object) -> object:
            return _Parsed()

        monkeypatch.setattr("waton.app.app.process_incoming_message", _parsed)

        @app.message()
        async def on_message(_ctx: Context) -> None:
            return None

        await app._dispatch_message(
            BinaryNode(
                tag="message",
                attrs={"id": "ingress-id", "from": "ingress@s.whatsapp.net", "type": "text"},
                content=b"ignored",
            )
        )

        trace_records = [record for record in caplog.records if getattr(record, "trace_id", None)]
        assert trace_records
        message_ids = {getattr(record, "message_id", None) for record in trace_records}
        assert message_ids == {"ingress-id"}

        await app.media.http.aclose()

    _run(_case())


def test_app_dispatch_logs_completion_and_middleware_exit_on_handler_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _case() -> None:
        caplog.set_level(logging.DEBUG, logger="waton.app.app")
        caplog.set_level(logging.DEBUG, logger="waton.app.middleware")
        caplog.set_level(logging.DEBUG, logger="waton.app.router")

        app = App(storage_path=":memory:")

        async def passthrough(_ctx: Context, nxt) -> None:
            await nxt()

        app.use(passthrough)

        @app.command("!ping")
        async def ping(_ctx: Context) -> None:
            raise RuntimeError("boom")

        msg = wa_pb2.Message()
        msg.conversation = "!ping crash"
        with pytest.raises(RuntimeError, match="boom"):
            await app._dispatch_message(
                BinaryNode(
                    tag="message",
                    attrs={"id": "m-crash", "from": "123@s.whatsapp.net", "type": "text"},
                    content=msg.SerializeToString(),
                )
            )

        trace_records = [record for record in caplog.records if getattr(record, "trace_id", None)]
        assert trace_records
        stages = [getattr(record, "stage", None) for record in trace_records]
        assert "middleware_enter" in stages
        assert "middleware_exit" in stages
        assert "dispatch_complete" in stages

        completion_records = [
            record
            for record in trace_records
            if getattr(record, "stage", None) == "dispatch_complete"
        ]
        assert len(completion_records) == 1
        assert getattr(completion_records[0], "dispatch_status", None) == "error"

        await app.media.http.aclose()

    _run(_case())
