import asyncio

from waton import simple
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import wa_pb2
from waton.simple_api import SimpleClient


def _run(coro):
    return asyncio.run(coro)


def test_waton_exports_simple_factory() -> None:
    client = simple(storage_path=":memory:")
    assert isinstance(client, SimpleClient)


def test_simple_on_message_wraps_context_and_reply() -> None:
    async def _case() -> None:
        client = simple(storage_path=":memory:")
        seen: dict[str, object] = {}

        async def _fake_send_text(to_jid: str, text: str) -> str:
            seen["reply"] = (to_jid, text)
            return "reply-mid"

        client.app.messages.send_text = _fake_send_text  # type: ignore[method-assign]

        observed: list[tuple[str, str | None, str, str]] = []

        @client.on_message
        async def on_message(msg):
            observed.append((msg.from_jid, msg.text, msg.sender, msg.id))
            seen["reply_id"] = await msg.reply("pong")

        proto = wa_pb2.Message()
        proto.conversation = "ping"
        node = BinaryNode(
            tag="message",
            attrs={"id": "m-simple-1", "from": "628111111111@s.whatsapp.net", "type": "text"},
            content=proto.SerializeToString(),
        )
        await client.app._dispatch_message(node)

        assert observed == [("628111111111@s.whatsapp.net", "ping", "628111111111@s.whatsapp.net", "m-simple-1")]
        assert seen["reply"] == ("628111111111@s.whatsapp.net", "pong")
        assert seen["reply_id"] == "reply-mid"
        await client.app.media.http.aclose()

    _run(_case())


def test_simple_on_ready_receives_simple_client() -> None:
    async def _case() -> None:
        client = simple(storage_path=":memory:")
        seen: list[SimpleClient] = []

        @client.on_ready
        async def on_ready(bound_client: SimpleClient) -> None:
            seen.append(bound_client)

        assert client.app._on_ready_cb is not None
        await client.app._on_ready_cb(client.app)
        assert seen == [client]
        await client.app.media.http.aclose()

    _run(_case())


def test_simple_send_text_delegates_to_app_messages_api() -> None:
    async def _case() -> None:
        client = simple(storage_path=":memory:")
        seen: dict[str, object] = {}

        async def _fake_send_text(to_jid: str, text: str) -> str:
            seen["payload"] = (to_jid, text)
            return "send-mid"

        client.app.messages.send_text = _fake_send_text  # type: ignore[method-assign]
        result = await client.send_text("628222222222@s.whatsapp.net", "halo")

        assert seen["payload"] == ("628222222222@s.whatsapp.net", "halo")
        assert result == "send-mid"
        await client.app.media.http.aclose()

    _run(_case())


def test_simple_on_message_rejects_non_async_handler() -> None:
    client = simple(storage_path=":memory:")

    def _sync_handler(_msg):
        return None

    try:
        client.on_message(_sync_handler)  # type: ignore[arg-type]
    except TypeError as exc:
        assert "async" in str(exc).lower()
    else:
        raise AssertionError("expected TypeError for non-async on_message handler")

    _run(client.app.media.http.aclose())


def test_simple_on_ready_rejects_non_async_handler() -> None:
    client = simple(storage_path=":memory:")

    def _sync_ready(_client):
        return None

    try:
        client.on_ready(_sync_ready)  # type: ignore[arg-type]
    except TypeError as exc:
        assert "async" in str(exc).lower()
    else:
        raise AssertionError("expected TypeError for non-async on_ready handler")

    _run(client.app.media.http.aclose())


def test_simple_send_text_rejects_empty_target_jid() -> None:
    async def _case() -> None:
        client = simple(storage_path=":memory:")
        try:
            await client.send_text("", "halo")
        except ValueError as exc:
            assert "to_jid" in str(exc)
        else:
            raise AssertionError("expected ValueError for empty to_jid")
        await client.app.media.http.aclose()

    _run(_case())
