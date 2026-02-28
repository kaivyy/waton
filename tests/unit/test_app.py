import asyncio

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


def test_app_dispatch_fallback_prefers_participant_as_sender_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
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

        assert seen == [("628111111111@s.whatsapp.net", "text", "628111111111@s.whatsapp.net")]
        await app.media.http.aclose()

    _run(_case())
