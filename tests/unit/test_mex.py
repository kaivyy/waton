import asyncio

from waton.client.mex import MexAPI
from waton.protocol.binary_node import BinaryNode


def _run(coro):
    return asyncio.run(coro)


class _DummyClient:
    def __init__(self) -> None:
        self.last_query: BinaryNode | None = None

    async def query(self, node: BinaryNode) -> BinaryNode:
        self.last_query = node
        return BinaryNode(
            tag="iq",
            attrs={"type": "result", "xmlns": "w:mex"},
            content=[BinaryNode(tag="mex", attrs={"id": "mex-ok", "status": "ok"})],
        )


def test_mex_query_builds_expected_envelope() -> None:
    async def _case() -> None:
        client = _DummyClient()
        api = MexAPI(client)  # type: ignore[arg-type]

        result = await api.query("health", {"mode": "quick"})

        assert result["id"] == "mex-ok"
        assert result["status"] == "ok"
        assert client.last_query is not None
        assert client.last_query.tag == "iq"
        assert client.last_query.attrs["xmlns"] == "w:mex"
        assert client.last_query.attrs["type"] == "get"
        payload = client.last_query.content[0]
        assert isinstance(payload, BinaryNode)
        assert payload.tag == "mex"
        assert payload.attrs["op"] == "health"
        assert payload.attrs["mode"] == "quick"

    _run(_case())


def test_mex_query_rejects_empty_operation() -> None:
    async def _case() -> None:
        client = _DummyClient()
        api = MexAPI(client)  # type: ignore[arg-type]

        try:
            await api.query("", {"mode": "quick"})
        except ValueError as exc:
            assert "operation" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError for empty operation")

    _run(_case())
