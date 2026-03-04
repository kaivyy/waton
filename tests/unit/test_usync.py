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

    def generate_message_tag(self) -> str:
        return self._generate_message_tag()

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
                                        BinaryNode(tag="picture", attrs={"id": "pic-123", "type": "image"}),
                                        BinaryNode(tag="business", attrs={"description": "Coffee shop"}),
                                        BinaryNode(
                                            tag="verified_name",
                                            attrs={"certificate": "valid", "name": "Arvy Biz"},
                                        ),
                                        BinaryNode(tag="device", attrs={"id": "0", "platform": "android"}),
                                        BinaryNode(tag="bot_profile", attrs={"type": "official", "tier": "verified"}),
                                        BinaryNode(tag="sidelist", attrs={"enabled": "true"}),
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


def test_usync_get_contact_status_lid_and_disappearing_mode() -> None:
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


def test_usync_query_builds_additional_profile_protocol_nodes() -> None:
    async def _case() -> None:
        client = _DummyClient()
        usync = USyncQuery(client)  # type: ignore[arg-type]

        await usync.get_picture_business_and_verified_name(["628111111111@s.whatsapp.net"])

        assert client.last_query is not None
        usync_node = client.last_query.content[0]
        assert isinstance(usync_node, BinaryNode)
        query = usync_node.content[0]
        assert isinstance(query, BinaryNode)
        tags = [child.tag for child in query.content]
        assert tags == ["picture", "business", "verified_name"]

    asyncio.run(_case())


def test_usync_get_picture_business_and_verified_name() -> None:
    async def _case() -> None:
        client = _DummyClient()
        usync = USyncQuery(client)  # type: ignore[arg-type]

        data = await usync.get_picture_business_and_verified_name(["628111111111@s.whatsapp.net"])

        row = data["628111111111@s.whatsapp.net"]
        assert row["picture"]["id"] == "pic-123"
        assert row["picture"]["type"] == "image"
        assert row["business"]["description"] == "Coffee shop"
        assert row["verified_name"]["certificate"] == "valid"
        assert row["verified_name"]["name"] == "Arvy Biz"

    asyncio.run(_case())


def test_usync_query_builds_extended_protocol_nodes() -> None:
    async def _case() -> None:
        client = _DummyClient()
        usync = USyncQuery(client)  # type: ignore[arg-type]

        await usync.get_device_and_bot_profile(["628111111111@s.whatsapp.net"])

        assert client.last_query is not None
        usync_node = client.last_query.content[0]
        assert isinstance(usync_node, BinaryNode)
        query = usync_node.content[0]
        assert isinstance(query, BinaryNode)
        tags = [child.tag for child in query.content]
        assert tags == ["device", "bot_profile", "sidelist"]

    asyncio.run(_case())


def test_usync_get_device_and_bot_profile() -> None:
    async def _case() -> None:
        client = _DummyClient()
        usync = USyncQuery(client)  # type: ignore[arg-type]

        data = await usync.get_device_and_bot_profile(["628111111111@s.whatsapp.net"])

        row = data["628111111111@s.whatsapp.net"]
        assert row["device"]["platform"] == "android"
        assert row["bot_profile"]["type"] == "official"
        assert row["bot_profile"]["tier"] == "verified"
        assert row["sidelist"]["enabled"] == "true"

    asyncio.run(_case())
