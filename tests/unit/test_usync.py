import asyncio

from waton.client.usync import USyncQuery
from waton.protocol.binary_node import BinaryNode


class _DummyClient:
    def __init__(self) -> None:
        self.last_query: BinaryNode | None = None
        self._counter = 0

    def _generate_message_tag(self) -> str:
        self._counter += 1
        return f"tag-{self._counter}"

    async def query(self, node: BinaryNode) -> BinaryNode:
        self.last_query = node
        return BinaryNode(
            tag="iq",
            attrs={"type": "result"},
            content=[
                BinaryNode(
                    tag="usync",
                    attrs={},
                    content=[
                        BinaryNode(
                            tag="list",
                            attrs={},
                            content=[
                                BinaryNode(
                                    tag="user",
                                    attrs={"jid": "628111111111@s.whatsapp.net"},
                                    content=[
                                        BinaryNode(
                                            tag="devices",
                                            attrs={},
                                            content=[
                                                BinaryNode(
                                                    tag="device-list",
                                                    attrs={},
                                                    content=[BinaryNode(tag="device", attrs={"id": "0"})],
                                                )
                                            ],
                                        ),
                                        BinaryNode(tag="contact", attrs={"name": "Arvy"}),
                                        BinaryNode(tag="status", attrs={"text": "available"}),
                                        BinaryNode(tag="lid", attrs={"jid": "179981124669483@lid"}),
                                        BinaryNode(tag="disappearing_mode", attrs={"duration": "604800"}),
                                    ],
                                )
                            ],
                        )
                    ],
                )
            ],
        )


def test_usync_query_builds_requested_protocol_nodes() -> None:
    async def _case() -> None:
        client = _DummyClient()
        usync = USyncQuery(client)  # type: ignore[arg-type]

        await usync.get_contact_status_lid_and_disappearing_mode(["628111111111@s.whatsapp.net"])

        assert client.last_query is not None
        assert client.last_query.tag == "iq"
        assert client.last_query.attrs["xmlns"] == "usync"
        usync_node = client.last_query.content[0]
        assert isinstance(usync_node, BinaryNode)
        query = usync_node.content[0]
        assert isinstance(query, BinaryNode)
        tags = [child.tag for child in query.content]
        assert tags == ["contact", "status", "lid", "disappearing_mode"]

    asyncio.run(_case())


def test_usync_get_contact_status_lid_and_disappearing_mode():
    async def _case() -> None:
        client = _DummyClient()
        usync = USyncQuery(client)  # type: ignore[arg-type]

        data = await usync.get_contact_status_lid_and_disappearing_mode(["628111111111@s.whatsapp.net"])

        assert "628111111111@s.whatsapp.net" in data
        row = data["628111111111@s.whatsapp.net"]
        assert row["contact"]["name"] == "Arvy"
        assert row["status"]["text"] == "available"
        assert row["lid"]["jid"] == "179981124669483@lid"
        assert row["disappearing_mode"]["duration"] == "604800"

    asyncio.run(_case())


def test_usync_get_devices_still_supported() -> None:
    async def _case() -> None:
        client = _DummyClient()
        usync = USyncQuery(client)  # type: ignore[arg-type]

        devices = await usync.get_devices(["628111111111@s.whatsapp.net"])

        assert devices["628111111111@s.whatsapp.net"] == ["628111111111:0@s.whatsapp.net"]

    asyncio.run(_case())
