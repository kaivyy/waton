import asyncio
from collections.abc import Awaitable
from typing import Any

from waton.client.newsletter import NewsletterAPI
from waton.protocol.binary_node import BinaryNode


class _FakeClient:
    def __init__(self) -> None:
        self.sent: list[BinaryNode] = []
        self.queried: list[BinaryNode] = []

    async def send_node(self, node: BinaryNode) -> None:
        self.sent.append(node)

    async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
        self.queried.append(node)
        return BinaryNode(
            tag="iq",
            attrs={"type": "result"},
            content=[BinaryNode(tag="newsletter", attrs={"jid": "112233@newsletter"}, content=[])],
        )


def _run(coro: Awaitable[Any]) -> Any:
    return asyncio.run(coro)


def test_create_newsletter_parses_jid_from_query() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = NewsletterAPI(client)
        jid = await api.create_newsletter("My News", "Desc")
        assert jid == "112233@newsletter"
        assert len(client.queried) == 1
        node = client.queried[0]
        assert node.tag == "iq"
        assert node.attrs["xmlns"] == "newsletter"

    _run(_case())


def test_follow_unfollow_and_mute_unmute_issue_queries() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = NewsletterAPI(client)
        await api.follow_newsletter("n@newsletter")
        await api.unfollow_newsletter("n@newsletter")
        await api.mute_newsletter("n@newsletter", mute=True)
        await api.mute_newsletter("n@newsletter", mute=False)

        assert len(client.sent) == 4
        assert client.sent[0].content[0].tag == "follow"
        assert client.sent[1].content[0].tag == "unfollow"
        assert client.sent[2].content[0].tag == "mute"
        assert client.sent[3].content[0].tag == "unmute"

    _run(_case())


def test_newsletter_metadata_and_update_helpers() -> None:
    class _MetaClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            if node.attrs.get("type") == "get":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[
                        BinaryNode(
                            tag="newsletter",
                            attrs={"jid": "112233@newsletter"},
                            content=[
                                BinaryNode(tag="name", attrs={}, content="News Name"),
                                BinaryNode(tag="description", attrs={}, content="News Desc"),
                            ],
                        )
                    ],
                )
            return BinaryNode(tag="iq", attrs={"type": "result"}, content=[])

    async def _case() -> None:
        client = _MetaClient()
        api = NewsletterAPI(client)
        metadata = await api.newsletter_metadata("112233@newsletter")
        assert metadata["jid"] == "112233@newsletter"
        assert metadata["name"] == "News Name"
        assert metadata["description"] == "News Desc"

        await api.newsletter_update_name("112233@newsletter", "Renamed")
        await api.newsletter_update_description("112233@newsletter", "Updated Desc")

        assert len(client.queried) == 3
        assert client.queried[1].attrs["type"] == "set"
        assert client.queried[2].attrs["type"] == "set"

    _run(_case())


def test_newsletter_react_message_builds_correct_nodes() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = NewsletterAPI(client)

        await api.newsletter_react_message("112233@newsletter", "srv-1", reaction="👍")
        await api.newsletter_react_message("112233@newsletter", "srv-1", reaction=None)

        assert len(client.queried) == 2
        reaction_node = client.queried[0]
        clear_node = client.queried[1]

        assert reaction_node.tag == "message"
        assert reaction_node.attrs["type"] == "reaction"
        assert reaction_node.attrs["server_id"] == "srv-1"
        assert "edit" not in reaction_node.attrs
        assert reaction_node.content[0].tag == "reaction"
        assert reaction_node.content[0].attrs["code"] == "👍"

        assert clear_node.tag == "message"
        assert clear_node.attrs["type"] == "reaction"
        assert clear_node.attrs["edit"] == "7"
        assert clear_node.content[0].tag == "reaction"
        assert clear_node.content[0].attrs == {}

    _run(_case())


def test_newsletter_fetch_messages_and_live_updates() -> None:
    class _FetchClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            first_child = node.content[0]
            if first_child.tag == "live_updates":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[BinaryNode(tag="live_updates", attrs={"duration": "300"})],
                )
            return BinaryNode(tag="iq", attrs={"type": "result"}, content=[])

    async def _case() -> None:
        client = _FetchClient()
        api = NewsletterAPI(client)

        await api.newsletter_fetch_messages("112233@newsletter", count=25, since=1700, after=1701)
        node = client.queried[0]
        assert node.tag == "iq"
        assert node.attrs["type"] == "get"
        assert node.attrs["xmlns"] == "newsletter"
        updates = node.content[0]
        assert updates.tag == "message_updates"
        assert updates.attrs["count"] == "25"
        assert updates.attrs["since"] == "1700"
        assert updates.attrs["after"] == "1701"

        live_updates = await api.subscribe_newsletter_updates("112233@newsletter")
        assert live_updates == {"duration": "300"}
        live_node = client.queried[1]
        assert live_node.tag == "iq"
        assert live_node.attrs["type"] == "set"
        assert live_node.content[0].tag == "live_updates"

    _run(_case())
