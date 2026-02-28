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
