import asyncio
from collections.abc import Awaitable
from typing import Any

from waton.client.groups import GroupsAPI
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
            content=[
                BinaryNode(
                    tag="group",
                    attrs={"id": "123456789@g.us"},
                    content=[],
                )
            ],
        )


def _run(coro: Awaitable[Any]) -> Any:
    return asyncio.run(coro)


def test_create_group_sends_iq_create() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = GroupsAPI(client)
        jid = await api.create_group("My Group", ["1@s.whatsapp.net", "2@s.whatsapp.net"])
        assert jid == "123456789@g.us"
        assert len(client.queried) == 1
        node = client.queried[0]
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


def test_group_metadata_and_fetch_all_participating() -> None:
    class _MetaClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            if node.attrs.get("to") == "@g.us":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[
                        BinaryNode(
                            tag="groups",
                            attrs={},
                            content=[
                                BinaryNode(tag="group", attrs={"id": "111111", "subject": "One", "creation": "10"}),
                                BinaryNode(
                                    tag="group",
                                    attrs={"id": "222222@g.us", "subject": "Two", "creation": "20"},
                                ),
                            ],
                        )
                    ],
                )
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="group",
                        attrs={"id": "333333", "subject": "Meta", "creation": "30"},
                        content=[BinaryNode(tag="participant", attrs={"jid": "1@s.whatsapp.net", "type": "admin"})],
                    )
                ],
            )

    async def _case() -> None:
        client = _MetaClient()
        api = GroupsAPI(client)
        meta = await api.group_metadata("333333@g.us")
        assert meta["id"] == "333333@g.us"
        assert meta["subject"] == "Meta"
        assert meta["participants"][0]["id"] == "1@s.whatsapp.net"

        all_groups = await api.group_fetch_all_participating()
        assert set(all_groups.keys()) == {"111111@g.us", "222222@g.us"}
        assert all_groups["111111@g.us"]["subject"] == "One"

    _run(_case())


def test_group_update_helpers_issue_wg2_queries() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = GroupsAPI(client)

        await api.group_update_subject("123@g.us", "New Subject")
        await api.group_update_description("123@g.us", "New Desc")
        await api.group_setting_update("123@g.us", "announcement")

        assert len(client.queried) == 3
        subject_node = client.queried[0].content[0]
        desc_node = client.queried[1].content[0]
        setting_node = client.queried[2].content[0]

        assert subject_node.tag == "subject"
        assert isinstance(subject_node.content, (bytes, bytearray))
        assert desc_node.tag == "description"
        assert setting_node.tag == "announcement"

    _run(_case())


def test_group_invite_helpers_parse_code() -> None:
    class _InviteClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[BinaryNode(tag="invite", attrs={"code": "ABCD1234"})],
            )

    async def _case() -> None:
        client = _InviteClient()
        api = GroupsAPI(client)
        assert await api.group_invite_code("123@g.us") == "ABCD1234"
        assert await api.group_revoke_invite("123@g.us") == "ABCD1234"

    _run(_case())


def test_group_ephemeral_and_membership_modes() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = GroupsAPI(client)
        await api.group_toggle_ephemeral("123@g.us", 86400)
        await api.group_toggle_ephemeral("123@g.us", 0)
        await api.group_member_add_mode("123@g.us", "all_member_add")
        await api.group_join_approval_mode("123@g.us", "on")

        assert len(client.queried) == 4
        assert client.queried[0].content[0].tag == "ephemeral"
        assert client.queried[0].content[0].attrs["expiration"] == "86400"
        assert client.queried[1].content[0].tag == "not_ephemeral"
        assert client.queried[2].content[0].tag == "member_add_mode"
        join_mode = client.queried[3].content[0]
        assert join_mode.tag == "membership_approval_mode"
        assert join_mode.content[0].tag == "group_join"
        assert join_mode.content[0].attrs["state"] == "on"

    _run(_case())


def test_group_accept_invite_and_get_invite_info() -> None:
    class _InviteInfoClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            is_set = node.attrs.get("type") == "set"
            if is_set and node.attrs.get("to") == "@g.us":
                return BinaryNode(
                    tag="iq",
                    attrs={"type": "result"},
                    content=[
                        BinaryNode(
                            tag="group",
                            attrs={"jid": "777777@g.us", "id": "777777", "subject": "Joined"},
                        )
                    ],
                )
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[BinaryNode(tag="group", attrs={"id": "888888", "subject": "Invite Info", "creation": "7"})],
            )

    async def _case() -> None:
        client = _InviteInfoClient()
        api = GroupsAPI(client)
        joined = await api.group_accept_invite("CODE123")
        assert joined == "777777@g.us"

        info = await api.group_get_invite_info("CODEXYZ")
        assert info["id"] == "888888@g.us"
        assert info["subject"] == "Invite Info"

    _run(_case())


def test_group_metadata_parses_extended_fields() -> None:
    class _ExtendedMetaClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="group",
                        attrs={
                            "id": "555555",
                            "subject": "Meta Group",
                            "creation": "42",
                            "notify": "Meta Notify",
                            "s_o": "111@s.whatsapp.net",
                            "s_t": "170",
                            "creator": "222@s.whatsapp.net",
                            "size": "3",
                        },
                        content=[
                            BinaryNode(
                                tag="description",
                                attrs={"id": "desc-1", "participant": "222@s.whatsapp.net", "t": "55"},
                                content=[BinaryNode(tag="body", attrs={}, content=b"Group Desc")],
                            ),
                            BinaryNode(tag="linked_parent", attrs={"jid": "parent@g.us"}),
                            BinaryNode(tag="locked", attrs={}),
                            BinaryNode(tag="announcement", attrs={}),
                            BinaryNode(tag="parent", attrs={}),
                            BinaryNode(tag="default_sub_group", attrs={}),
                            BinaryNode(tag="membership_approval_mode", attrs={}),
                            BinaryNode(tag="member_add_mode", attrs={}, content=b"all_member_add"),
                            BinaryNode(tag="ephemeral", attrs={"expiration": "86400"}),
                            BinaryNode(tag="participant", attrs={"jid": "1@s.whatsapp.net", "type": "admin"}),
                            BinaryNode(tag="participant", attrs={"jid": "2@s.whatsapp.net", "type": "superadmin"}),
                        ],
                    )
                ],
            )

    async def _case() -> None:
        client = _ExtendedMetaClient()
        api = GroupsAPI(client)
        meta = await api.group_metadata("555555@g.us")
        assert meta["id"] == "555555@g.us"
        assert meta["notify"] == "Meta Notify"
        assert meta["subject_owner"] == "111@s.whatsapp.net"
        assert meta["subject_time"] == 170
        assert meta["owner"] == "222@s.whatsapp.net"
        assert meta["size"] == 3
        assert meta["description"] == "Group Desc"
        assert meta["desc_id"] == "desc-1"
        assert meta["desc_owner"] == "222@s.whatsapp.net"
        assert meta["desc_time"] == 55
        assert meta["linked_parent"] == "parent@g.us"
        assert meta["restrict"] is True
        assert meta["announce"] is True
        assert meta["is_community"] is True
        assert meta["is_community_announce"] is True
        assert meta["join_approval_mode"] is True
        assert meta["member_add_mode"] is True
        assert meta["ephemeral_duration"] == 86400
        assert len(meta["participants"]) == 2
        assert meta["participants"][0]["admin"] == "admin"

    _run(_case())


def test_group_request_participants_list_and_update() -> None:
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

            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="membership_requests_action",
                        attrs={},
                        content=[
                            BinaryNode(
                                tag="approve",
                                attrs={},
                                content=[
                                    BinaryNode(tag="participant", attrs={"jid": "1@s.whatsapp.net"}),
                                    BinaryNode(tag="participant", attrs={"jid": "2@s.whatsapp.net", "error": "403"}),
                                ],
                            )
                        ],
                    )
                ],
            )

    async def _case() -> None:
        client = _RequestClient()
        api = GroupsAPI(client)
        requested = await api.group_request_participants_list("123@g.us")
        assert requested == [{"jid": "1@s.whatsapp.net"}, {"jid": "2@s.whatsapp.net"}]

        updated = await api.group_request_participants_update(
            "123@g.us",
            ["1@s.whatsapp.net", "2@s.whatsapp.net"],
            "approve",
        )
        assert updated == [
            {"status": "200", "jid": "1@s.whatsapp.net"},
            {"status": "403", "jid": "2@s.whatsapp.net"},
        ]

    _run(_case())


def test_group_participants_update_and_revoke_invite_v4() -> None:
    class _ParticipantsClient(_FakeClient):
        async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
            self.queried.append(node)
            action_node = node.content[0]
            if action_node.tag == "revoke":
                return BinaryNode(tag="iq", attrs={"type": "result"}, content=[])
            return BinaryNode(
                tag="iq",
                attrs={"type": "result"},
                content=[
                    BinaryNode(
                        tag="add",
                        attrs={},
                        content=[
                            BinaryNode(tag="participant", attrs={"jid": "1@s.whatsapp.net"}),
                            BinaryNode(tag="participant", attrs={"jid": "2@s.whatsapp.net", "error": "409"}),
                        ],
                    )
                ],
            )

    async def _case() -> None:
        client = _ParticipantsClient()
        api = GroupsAPI(client)

        result = await api.group_participants_update("123@g.us", ["1@s.whatsapp.net", "2@s.whatsapp.net"], "add")
        assert result[0]["status"] == "200"
        assert result[0]["jid"] == "1@s.whatsapp.net"
        assert result[1]["status"] == "409"
        assert result[1]["jid"] == "2@s.whatsapp.net"
        assert isinstance(result[0]["content"], BinaryNode)

        ok = await api.group_revoke_invite_v4("123@g.us", "1@s.whatsapp.net")
        assert ok is True
        revoke_node = client.queried[1].content[0]
        assert revoke_node.tag == "revoke"
        assert revoke_node.content[0].attrs["jid"] == "1@s.whatsapp.net"

    _run(_case())

