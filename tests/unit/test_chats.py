import asyncio

from waton.client.chats import ChatsAPI
from waton.client.presence import PresenceAPI
from waton.protocol.binary_node import BinaryNode
from waton.utils.chat_utils import is_group_chat, is_private_chat, normalize_chat_jid


class _FakeClient:
    def __init__(self) -> None:
        self.sent: list[BinaryNode] = []

    async def send_node(self, node: BinaryNode) -> None:
        self.sent.append(node)


def _run(coro):
    return asyncio.run(coro)


def test_chats_presence_update() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = ChatsAPI(client)
        await api.send_presence_update("123@s.whatsapp.net", "composing")
        assert len(client.sent) == 1
        node = client.sent[0]
        assert node.tag == "presence"
        assert node.attrs["to"] == "123@s.whatsapp.net"
        assert node.attrs["type"] == "composing"

    _run(_case())


def test_presence_api_helpers() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = PresenceAPI(client)
        await api.send_available("1@s.whatsapp.net")
        await api.send_paused("1@s.whatsapp.net")
        assert [n.attrs["type"] for n in client.sent] == ["available", "paused"]

    _run(_case())


def test_chat_utils() -> None:
    assert is_private_chat("123@s.whatsapp.net")
    assert not is_private_chat("123@g.us")
    assert is_group_chat("123-456@g.us")
    assert normalize_chat_jid("123:2@s.whatsapp.net") == "123@s.whatsapp.net"

