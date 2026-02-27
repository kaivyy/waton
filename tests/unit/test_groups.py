import asyncio

from waton.client.groups import GroupsAPI
from waton.protocol.binary_node import BinaryNode


class _FakeClient:
    def __init__(self) -> None:
        self.sent: list[BinaryNode] = []

    async def send_node(self, node: BinaryNode) -> None:
        self.sent.append(node)


def _run(coro):
    return asyncio.run(coro)


def test_create_group_sends_iq_create() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = GroupsAPI(client)
        jid = await api.create_group("My Group", ["1@s.whatsapp.net", "2@s.whatsapp.net"])
        assert jid.endswith("@g.us")
        assert len(client.sent) == 1
        node = client.sent[0]
        assert node.tag == "iq"
        assert node.attrs["xmlns"] == "w:g2"
        create_node = node.content[0]
        assert create_node.tag == "create"
        assert len(create_node.content) == 2

    _run(_case())


def test_add_and_leave_group() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = GroupsAPI(client)
        await api.add_participants("x@g.us", ["1@s.whatsapp.net"])
        await api.leave_group("x@g.us")
        assert len(client.sent) == 2
        assert client.sent[0].content[0].tag == "add"
        assert client.sent[1].content[0].tag == "leave"

    _run(_case())

