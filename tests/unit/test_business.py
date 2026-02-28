import asyncio

from waton.client.business import BusinessAPI
from waton.protocol.binary_node import BinaryNode


def _run(coro):
    return asyncio.run(coro)


class _DummyClient:
    def __init__(self) -> None:
        self.last_query: BinaryNode | None = None

    async def query(self, node: BinaryNode) -> BinaryNode:
        self.last_query = node
        if node.attrs.get("type") == "get":
            child = node.content[0] if isinstance(node.content, list) and node.content else None
            if isinstance(child, BinaryNode) and child.tag == "catalog":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[BinaryNode(tag="catalog", attrs={"jid": "628111111111@s.whatsapp.net", "status": "available"})],
                )
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="business_profile",
                        attrs={
                            "jid": "628111111111@s.whatsapp.net",
                            "name": "Toko Saya",
                            "description": "Kebutuhan harian",
                            "email": "halo@example.com",
                            "category": "retail",
                            "address": "Jakarta",
                            "website": "https://example.com",
                            "hours": "09:00-18:00",
                        },
                    )
                ],
            )
        return BinaryNode(tag="iq", attrs={"type": "result"}, content=[])


def test_business_profile_fetch_parses_response() -> None:
    async def _case() -> None:
        client = _DummyClient()
        api = BusinessAPI(client)  # type: ignore[arg-type]

        profile = await api.business_profile("628111111111@s.whatsapp.net")

        assert profile["jid"] == "628111111111@s.whatsapp.net"
        assert profile["name"] == "Toko Saya"
        assert profile["description"] == "Kebutuhan harian"
        assert profile["email"] == "halo@example.com"
        assert profile["category"] == "retail"
        assert profile["address"] == "Jakarta"
        assert profile["website"] == "https://example.com"
        assert profile["hours"] == "09:00-18:00"
        assert client.last_query is not None
        assert client.last_query.tag == "iq"
        assert client.last_query.attrs["xmlns"] == "w:biz"
        assert client.last_query.attrs["type"] == "get"

    _run(_case())


def test_business_profile_update_builds_valid_envelope() -> None:
    async def _case() -> None:
        client = _DummyClient()
        api = BusinessAPI(client)  # type: ignore[arg-type]

        await api.update_business_profile(
            "628111111111@s.whatsapp.net",
            name="Toko Baru",
            description="Deskripsi Baru",
            email="baru@example.com",
            category="services",
            address="Bandung",
            website="https://baru.example.com",
            hours="10:00-20:00",
        )

        assert client.last_query is not None
        assert client.last_query.tag == "iq"
        assert client.last_query.attrs["xmlns"] == "w:biz"
        assert client.last_query.attrs["type"] == "set"
        profile = client.last_query.content[0]
        assert isinstance(profile, BinaryNode)
        assert profile.tag == "business_profile"
        assert profile.attrs["jid"] == "628111111111@s.whatsapp.net"
        assert profile.attrs["name"] == "Toko Baru"
        assert profile.attrs["description"] == "Deskripsi Baru"
        assert profile.attrs["email"] == "baru@example.com"
        assert profile.attrs["category"] == "services"
        assert profile.attrs["address"] == "Bandung"
        assert profile.attrs["website"] == "https://baru.example.com"
        assert profile.attrs["hours"] == "10:00-20:00"

    _run(_case())


def test_business_profile_update_requires_non_empty_jid() -> None:
    async def _case() -> None:
        client = _DummyClient()
        api = BusinessAPI(client)  # type: ignore[arg-type]

        try:
            await api.update_business_profile("", name="X")
        except ValueError as exc:
            assert "jid" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError for empty jid")

    _run(_case())


def test_business_catalog_query_returns_catalog_attrs() -> None:
    async def _case() -> None:
        client = _DummyClient()
        api = BusinessAPI(client)  # type: ignore[arg-type]

        catalog = await api.business_catalog("628111111111@s.whatsapp.net")

        assert catalog["jid"] == "628111111111@s.whatsapp.net"
        assert catalog["status"] == "available"

    _run(_case())


def test_business_order_status_update_validates_input() -> None:
    async def _case() -> None:
        client = _DummyClient()
        api = BusinessAPI(client)  # type: ignore[arg-type]

        try:
            await api.update_order_status("628111111111@s.whatsapp.net", order_id="", status="accepted")
        except ValueError as exc:
            assert "order_id" in str(exc)
        else:
            raise AssertionError("expected ValueError for empty order_id")

    _run(_case())
