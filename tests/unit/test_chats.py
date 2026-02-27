import asyncio

import pytest

from waton.client.chats import ChatsAPI
from waton.client.presence import PresenceAPI
from waton.protocol.binary_node import BinaryNode
from waton.utils.chat_utils import is_group_chat, is_private_chat, normalize_chat_jid


class _FakeClient:
    def __init__(self) -> None:
        self.sent: list[BinaryNode] = []
        self.queried: list[BinaryNode] = []

    async def send_node(self, node: BinaryNode) -> None:
        self.sent.append(node)

    async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
        del timeout
        self.queried.append(node)
        if node.attrs.get("xmlns") == "w:profile:picture":
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[BinaryNode(tag="picture", attrs={"url": "https://cdn.example/p.jpg"})],
            )
        if node.attrs.get("xmlns") == "blocklist":
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="list",
                        attrs={},
                        content=[
                            BinaryNode(tag="item", attrs={"jid": "111@s.whatsapp.net"}),
                            BinaryNode(tag="item", attrs={"jid": "222@s.whatsapp.net"}),
                        ],
                    )
                ],
            )
        if node.attrs.get("xmlns") == "privacy":
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="privacy",
                        attrs={},
                        content=[BinaryNode(tag="category", attrs={"name": "last", "value": "contacts"})],
                    )
                ],
            )
        return BinaryNode(tag="iq", attrs={"type": "result"}, content=[])


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


def test_chats_profile_picture_and_blocklist() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = ChatsAPI(client)
        photo = await api.get_profile_picture("123@s.whatsapp.net")
        blocked = await api.fetch_blocklist()
        assert photo == "https://cdn.example/p.jpg"
        assert blocked == ["111@s.whatsapp.net", "222@s.whatsapp.net"]

    _run(_case())


def test_chats_profile_and_privacy_updates() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = ChatsAPI(client)

        await api.update_profile_status("hello status")
        await api.update_profile_name("my name")
        await api.presence_subscribe("123@s.whatsapp.net")
        await api.update_last_seen_privacy("contacts")
        await api.update_read_receipts_privacy("all")

        assert len(client.sent) >= 3
        assert any(n.tag == "presence" for n in client.sent)
        assert any(n.tag == "iq" and n.attrs.get("xmlns") == "status" for n in client.sent)
        assert any(n.tag == "iq" and n.attrs.get("xmlns") == "profile" for n in client.sent)
        assert len(client.queried) >= 2

    _run(_case())


def test_chats_fetch_privacy_settings() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = ChatsAPI(client)
        settings = await api.fetch_privacy_settings()
        assert settings["last"] == "contacts"

    _run(_case())


def test_chat_modify_supported_actions_emit_query() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = ChatsAPI(client)

        await api.chat_modify("123@s.whatsapp.net", "archive")
        await api.chat_modify("123@s.whatsapp.net", "unarchive")
        await api.chat_modify("123@s.whatsapp.net", "pin")
        await api.chat_modify("123@s.whatsapp.net", "unpin")
        await api.chat_modify("123@s.whatsapp.net", "mute")
        await api.chat_modify("123@s.whatsapp.net", "unmute")
        await api.chat_modify("123@s.whatsapp.net", "read")
        await api.chat_modify("123@s.whatsapp.net", "unread")

        assert len(client.queried) >= 8
        last = client.queried[-1]
        assert last.tag == "iq"
        assert last.attrs.get("type") == "set"
        assert last.attrs.get("xmlns") == "w:chat"
        assert isinstance(last.content, list)
        chat_node = last.content[0]
        assert chat_node.tag == "chat"
        assert chat_node.attrs.get("jid") == "123@s.whatsapp.net"
        assert isinstance(chat_node.content, list)
        op_node = chat_node.content[0]
        assert op_node.tag == "mark"
        assert op_node.attrs.get("type") == "unread"

    _run(_case())


def test_chat_modify_unknown_action_raises() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = ChatsAPI(client)
        with pytest.raises(ValueError, match="Unsupported chat modify action"):
            await api.chat_modify("123@s.whatsapp.net", "something-invalid")

    _run(_case())

