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
