import asyncio
from collections.abc import Awaitable
from typing import Any

from waton.client.communities import CommunitiesAPI
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
            content=[BinaryNode(tag="community", attrs={"jid": "999999@g.us"}, content=[])],
        )


def _run(coro: Awaitable[Any]) -> Any:
    return asyncio.run(coro)


def test_create_community_parses_jid_from_query() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = CommunitiesAPI(client)
        jid = await api.create_community("My Community", "Desc")
        assert jid == "999999@g.us"
        assert len(client.queried) == 1
        node = client.queried[0]
        assert node.tag == "iq"
        assert node.attrs["xmlns"] == "w:g2"

    _run(_case())


def test_community_metadata_and_fetch_all_participating() -> None:
    class _MetaClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            if node.attrs.get("to") == "@g.us":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[
                        BinaryNode(
                            tag="communities",
                            attrs={},
                            content=[
                                BinaryNode(tag="community", attrs={"id": "888888", "subject": "A", "creation": "11"}),
                                BinaryNode(
                                    tag="community",
                                    attrs={"id": "999999@g.us", "subject": "B", "creation": "22"},
                                ),
                            ],
                        )
                    ],
                )
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[BinaryNode(tag="community", attrs={"id": "777777", "subject": "Meta", "creation": "33"})],
            )

    async def _case() -> None:
        client = _MetaClient()
        api = CommunitiesAPI(client)
        meta = await api.community_metadata("777777@g.us")
        assert meta["id"] == "777777@g.us"
        assert meta["subject"] == "Meta"

        all_communities = await api.community_fetch_all_participating()
        assert set(all_communities.keys()) == {"888888@g.us", "999999@g.us"}

    _run(_case())


def test_community_update_and_invite_helpers() -> None:
    class _InviteClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[BinaryNode(tag="invite", attrs={"code": "COMM123"})],
            )

    async def _case() -> None:
        client = _InviteClient()
        api = CommunitiesAPI(client)
        await api.community_update_subject("c@g.us", "New Community Subject")
        await api.community_update_description("c@g.us", "New Community Desc")
        await api.community_setting_update("c@g.us", "locked")
        assert await api.community_invite_code("c@g.us") == "COMM123"
        assert await api.community_revoke_invite("c@g.us") == "COMM123"
        assert len(client.queried) == 5

    _run(_case())


def test_community_ephemeral_and_membership_modes() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = CommunitiesAPI(client)
        await api.community_toggle_ephemeral("c@g.us", 604800)
        await api.community_toggle_ephemeral("c@g.us", 0)
        await api.community_member_add_mode("c@g.us", "admin_add")
        await api.community_join_approval_mode("c@g.us", "off")

        assert len(client.queried) == 4
        assert client.queried[0].content[0].tag == "ephemeral"
        assert client.queried[1].content[0].tag == "not_ephemeral"
        assert client.queried[2].content[0].tag == "member_add_mode"
        join_mode = client.queried[3].content[0]
        assert join_mode.tag == "membership_approval_mode"
        assert join_mode.content[0].tag == "community_join"
        assert join_mode.content[0].attrs["state"] == "off"

    _run(_case())


def test_community_accept_invite_and_get_invite_info() -> None:
    class _InviteInfoClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            is_set = node.attrs.get("type") == "set"
            if is_set and node.attrs.get("to") == "@g.us":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[
                        BinaryNode(tag="community", attrs={"jid": "999111@g.us", "id": "999111", "subject": "Joined"})
                    ],
                )
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="community",
                        attrs={"id": "123123", "subject": "Invite Info", "creation": "9"},
                    )
                ],
            )

    async def _case() -> None:
        client = _InviteInfoClient()
        api = CommunitiesAPI(client)
        joined = await api.community_accept_invite("COMM-CODE")
        assert joined == "999111@g.us"

        info = await api.community_get_invite_info("COMM-CODE-2")
        assert info["id"] == "123123@g.us"
        assert info["subject"] == "Invite Info"

    _run(_case())


def test_community_metadata_parses_extended_fields() -> None:
    class _ExtendedMetaClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="community",
                        attrs={
                            "id": "444444",
                            "subject": "Community Meta",
                            "creation": "77",
                            "s_o": "111@s.whatsapp.net",
                            "s_t": "171",
                            "creator": "222@s.whatsapp.net",
                            "size": "2",
                        },
                        content=[
                            BinaryNode(
                                tag="description",
                                attrs={"id": "c-desc-1", "participant": "222@s.whatsapp.net", "t": "91"},
                                content=[BinaryNode(tag="body", attrs={}, content=b"Community Desc")],
                            ),
                            BinaryNode(tag="linked_parent", attrs={"jid": "root@g.us"}),
                            BinaryNode(tag="locked", attrs={}),
                            BinaryNode(tag="announcement", attrs={}),
                            BinaryNode(tag="parent", attrs={}),
                            BinaryNode(tag="default_sub_community", attrs={}),
                            BinaryNode(tag="membership_approval_mode", attrs={}),
                            BinaryNode(tag="member_add_mode", attrs={}, content=b"all_member_add"),
                            BinaryNode(tag="ephemeral", attrs={"expiration": "604800"}),
                            BinaryNode(tag="participant", attrs={"jid": "1@s.whatsapp.net", "type": "admin"}),
                        ],
                    )
                ],
            )

    async def _case() -> None:
        client = _ExtendedMetaClient()
        api = CommunitiesAPI(client)
        meta = await api.community_metadata("444444@g.us")
        assert meta["id"] == "444444@g.us"
        assert meta["subject"] == "Community Meta"
        assert meta["description"] == "Community Desc"
        assert meta["desc_id"] == "c-desc-1"
        assert meta["desc_owner"] == "222@s.whatsapp.net"
        assert meta["desc_time"] == 91
        assert meta["subject_owner"] == "111@s.whatsapp.net"
        assert meta["subject_time"] == 171
        assert meta["owner"] == "222@s.whatsapp.net"
        assert meta["size"] == 2
        assert meta["linked_parent"] == "root@g.us"
        assert meta["restrict"] is True
        assert meta["announce"] is True
        assert meta["is_community"] is True
        assert meta["is_community_announce"] is True
        assert meta["join_approval_mode"] is True
        assert meta["member_add_mode"] is True
        assert meta["ephemeral_duration"] == 604800
        assert meta["participants"][0]["jid"] == "1@s.whatsapp.net"

    _run(_case())


def test_community_create_group_and_link_helpers() -> None:
    class _CommunityGroupClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            create_node = node.content[0]
            if create_node.tag == "create":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[BinaryNode(tag="community", attrs={"id": "555000", "subject": "Sub Group"})],
                )
            if create_node.tag == "sub_groups":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[
                        BinaryNode(
                            tag="sub_groups",
                            attrs={},
                            content=[
                                BinaryNode(
                                    tag="group",
                                    attrs={
                                        "id": "111111",
                                        "subject": "A",
                                        "creation": "10",
                                        "creator": "1@s.whatsapp.net",
                                        "size": "7",
                                    },
                                ),
                                BinaryNode(
                                    tag="group",
                                    attrs={
                                        "id": "222222",
                                        "subject": "B",
                                        "creation": "20",
                                        "creator": "2@s.whatsapp.net",
                                        "size": "5",
                                    },
                                ),
                            ],
                        )
                    ],
                )
            return BinaryNode(tag="iq", attrs={"type": "result"}, content=[])

    async def _case() -> None:
        client = _CommunityGroupClient()
        api = CommunitiesAPI(client)
        group_jid = await api.community_create_group(
            "Sub Group",
            ["1@s.whatsapp.net", "2@s.whatsapp.net"],
            "444444@g.us",
        )
        assert group_jid == "555000@g.us"
        create_node = client.queried[0].content[0]
        assert create_node.tag == "create"
        assert create_node.content[-1].tag == "linked_parent"
        assert create_node.content[-1].attrs["jid"] == "444444@g.us"

        await api.community_link_group("111111@g.us", "444444@g.us")
        await api.community_unlink_group("111111@g.us", "444444@g.us")
        assert client.queried[1].content[0].tag == "links"
        assert client.queried[2].content[0].tag == "unlink"

        linked = await api.community_fetch_linked_groups("444444@g.us")
        assert linked["community_jid"] == "444444@g.us"
        assert linked["is_community"] is True
        assert len(linked["linked_groups"]) == 2
        assert linked["linked_groups"][0]["id"] == "111111@g.us"

    _run(_case())


def test_community_participant_request_and_update_helpers() -> None:
    class _RequestClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            query_node = node.content[0]
            if query_node.tag == "membership_approval_requests":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[
                        BinaryNode(
                            tag="membership_approval_requests",
                            attrs={},
                            content=[
                                BinaryNode(tag="membership_approval_request", attrs={"jid": "1@s.whatsapp.net"}),
                                BinaryNode(tag="membership_approval_request", attrs={"jid": "2@s.whatsapp.net"}),
                            ],
                        )
                    ],
                )
            if query_node.tag == "membership_requests_action":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[
                        BinaryNode(
                            tag="membership_requests_action",
                            attrs={},
                            content=[
                                BinaryNode(
                                    tag="reject",
                                    attrs={},
                                    content=[
                                        BinaryNode(tag="participant", attrs={"jid": "1@s.whatsapp.net"}),
                                        BinaryNode(tag="participant", attrs={"jid": "2@s.whatsapp.net", "error": "404"}),
                                    ],
                                )
                            ],
                        )
                    ],
                )

            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="remove",
                        attrs={},
                        content=[BinaryNode(tag="participant", attrs={"jid": "1@s.whatsapp.net"})],
                    )
                ],
            )

    async def _case() -> None:
        client = _RequestClient()
        api = CommunitiesAPI(client)
        requested = await api.community_request_participants_list("c@g.us")
        assert requested == [{"jid": "1@s.whatsapp.net"}, {"jid": "2@s.whatsapp.net"}]

        updated = await api.community_request_participants_update(
            "c@g.us",
            ["1@s.whatsapp.net", "2@s.whatsapp.net"],
            "reject",
        )
        assert updated == [
            {"status": "200", "jid": "1@s.whatsapp.net"},
            {"status": "404", "jid": "2@s.whatsapp.net"},
        ]

        participants = await api.community_participants_update("c@g.us", ["1@s.whatsapp.net"], "remove")
        assert participants[0]["status"] == "200"
        update_node = client.queried[2].content[0]
        assert update_node.tag == "remove"
        assert update_node.attrs["linked_groups"] == "true"

    _run(_case())
