import os
from typing import Any

from waton.client.client import WAClient
from waton.protocol.binary_node import BinaryNode


class GroupsAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def group_metadata(self, jid: str) -> dict[str, Any]:
        result = await self._group_query(
            jid,
            "get",
            [BinaryNode(tag="query", attrs={"request": "interactive"})],
        )
        group_node = self._find_child(result, "group")
        if group_node is None:
            raise ValueError("group metadata response missing group node")
        return self._parse_group_node(group_node)

    async def group_fetch_all_participating(self) -> dict[str, dict[str, Any]]:
        result = await self._group_query(
            "@g.us",
            "get",
            [
                BinaryNode(
                    tag="participating",
                    attrs={},
                    content=[
                        BinaryNode(tag="participants", attrs={}),
                        BinaryNode(tag="description", attrs={}),
                    ],
                )
            ],
        )
        groups_node = self._find_child(result, "groups")
        if groups_node is None:
            return {}

        data: dict[str, dict[str, Any]] = {}
        for node in self._find_children(groups_node, "group"):
            parsed = self._parse_group_node(node)
            data[parsed["id"]] = parsed
        return data

    async def create_group(self, subject: str, participants: list[str]) -> str:
        """Creates a new group and returns its JID from server response."""
        create_id = os.urandom(6).hex()

        participant_nodes = [BinaryNode(tag="participant", attrs={"jid": p}) for p in participants]
        group_node = BinaryNode(
            tag="create",
            attrs={"subject": subject},
            content=participant_nodes,
        )

        node = BinaryNode(
            tag="iq",
            attrs={"to": "@g.us", "type": "set", "xmlns": "w:g2", "id": create_id},
            content=[group_node],
        )
        res = await self.client.query(node)
        jid = self._extract_group_jid(res)
        if not jid:
            raise ValueError("create_group response missing group jid")
        return jid

    async def group_update_subject(self, jid: str, subject: str) -> None:
        await self._group_query(jid, "set", [BinaryNode(tag="subject", attrs={}, content=subject.encode("utf-8"))])

    async def group_update_description(self, jid: str, description: str | None) -> None:
        attrs = {"id": os.urandom(6).hex()} if description else {"delete": "true"}
        content = [BinaryNode(tag="body", attrs={}, content=description.encode("utf-8"))] if description else None
        await self._group_query(jid, "set", [BinaryNode(tag="description", attrs=attrs, content=content)])

    async def group_setting_update(self, jid: str, setting: str) -> None:
        await self._group_query(jid, "set", [BinaryNode(tag=setting, attrs={})])

    async def group_toggle_ephemeral(self, jid: str, ephemeral_expiration: int) -> None:
        content = (
            BinaryNode(tag="ephemeral", attrs={"expiration": str(ephemeral_expiration)})
            if ephemeral_expiration
            else BinaryNode(tag="not_ephemeral", attrs={})
        )
        await self._group_query(jid, "set", [content])

    async def group_member_add_mode(self, jid: str, mode: str) -> None:
        await self._group_query(jid, "set", [BinaryNode(tag="member_add_mode", attrs={}, content=mode)])

    async def group_join_approval_mode(self, jid: str, mode: str) -> None:
        await self._group_query(
            jid,
            "set",
            [
                BinaryNode(
                    tag="membership_approval_mode",
                    attrs={},
                    content=[BinaryNode(tag="group_join", attrs={"state": mode})],
                )
            ],
        )

    async def group_request_participants_list(self, jid: str) -> list[dict[str, str]]:
        result = await self._group_query(jid, "get", [BinaryNode(tag="membership_approval_requests", attrs={})])
        requests_node = self._find_child(result, "membership_approval_requests")
        return [dict(node.attrs) for node in self._find_children(requests_node, "membership_approval_request")]

    async def group_request_participants_update(
        self,
        jid: str,
        participants: list[str],
        action: str,
    ) -> list[dict[str, str]]:
        result = await self._group_query(
            jid,
            "set",
            [
                BinaryNode(
                    tag="membership_requests_action",
                    attrs={},
                    content=[
                        BinaryNode(
                            tag=action,
                            attrs={},
                            content=[BinaryNode(tag="participant", attrs={"jid": value}) for value in participants],
                        )
                    ],
                )
            ],
        )
        requests_action = self._find_child(result, "membership_requests_action")
        selected_action = self._find_child(requests_action, action)
        return [
            {"status": node.attrs.get("error", "200"), "jid": node.attrs.get("jid", "")}
            for node in self._find_children(selected_action, "participant")
        ]

    async def group_participants_update(
        self,
        jid: str,
        participants: list[str],
        action: str,
    ) -> list[dict[str, Any]]:
        result = await self._group_query(
            jid,
            "set",
            [BinaryNode(tag=action, attrs={}, content=[BinaryNode(tag="participant", attrs={"jid": value}) for value in participants])],
        )
        action_node = self._find_child(result, action)
        return [
            {
                "status": node.attrs.get("error", "200"),
                "jid": node.attrs.get("jid"),
                "content": node,
            }
            for node in self._find_children(action_node, "participant")
        ]

    async def group_invite_code(self, jid: str) -> str | None:
        result = await self._group_query(jid, "get", [BinaryNode(tag="invite", attrs={})])
        invite = self._find_child(result, "invite")
        return invite.attrs.get("code") if invite else None

    async def group_revoke_invite(self, jid: str) -> str | None:
        result = await self._group_query(jid, "set", [BinaryNode(tag="invite", attrs={})])
        invite = self._find_child(result, "invite")
        return invite.attrs.get("code") if invite else None

    async def group_revoke_invite_v4(self, group_jid: str, invited_jid: str) -> bool:
        result = await self._group_query(
            group_jid,
            "set",
            [
                BinaryNode(
                    tag="revoke",
                    attrs={},
                    content=[BinaryNode(tag="participant", attrs={"jid": invited_jid})],
                )
            ],
        )
        return result is not None

    async def group_accept_invite(self, code: str) -> str | None:
        result = await self._group_query("@g.us", "set", [BinaryNode(tag="invite", attrs={"code": code})])
        group = self._find_child(result, "group")
        if not group:
            return None
        group_jid = group.attrs.get("jid") or group.attrs.get("id")
        if not isinstance(group_jid, str):
            return None
        return self._normalize_group_jid(group_jid)

    async def group_get_invite_info(self, code: str) -> dict[str, Any]:
        result = await self._group_query("@g.us", "get", [BinaryNode(tag="invite", attrs={"code": code})])
        group_node = self._find_child(result, "group")
        if group_node is None:
            raise ValueError("invite info response missing group node")
        return self._parse_group_node(group_node)

    async def leave_group(self, group_jid: str) -> None:
        """Leaves a group chat."""
        leave_id = os.urandom(6).hex()
        node = BinaryNode(
            tag="iq",
            attrs={"to": group_jid, "type": "set", "xmlns": "w:g2", "id": leave_id},
            content=[BinaryNode(tag="leave", attrs={})],
        )
        await self.client.send_node(node)

    async def add_participants(self, group_jid: str, participants: list[str]) -> None:
        """Adds participants to a group."""
        participant_nodes = [BinaryNode(tag="participant", attrs={"jid": p}) for p in participants]
        add_node = BinaryNode(tag="add", attrs={}, content=participant_nodes)

        node = BinaryNode(
            tag="iq",
            attrs={"to": group_jid, "type": "set", "xmlns": "w:g2"},
            content=[add_node],
        )
        await self.client.send_node(node)

    async def _group_query(self, jid: str, request_type: str, content: list[BinaryNode]) -> BinaryNode:
        query_id = os.urandom(6).hex()
        return await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={"to": jid, "type": request_type, "xmlns": "w:g2", "id": query_id},
                content=content,
            )
        )

    @classmethod
    def _parse_group_node(cls, group_node: BinaryNode) -> dict[str, Any]:
        group_id = cls._normalize_group_jid(group_node.attrs.get("id"))
        description_node = cls._find_child(group_node, "description")
        body_node = cls._find_child(description_node, "body") if description_node else None
        description = cls._content_to_str(body_node.content) if body_node else None
        desc_time = cls._to_int(description_node.attrs.get("t")) if description_node else 0
        subject_time = cls._to_int(group_node.attrs.get("s_t"))
        member_add_mode = cls._find_child(group_node, "member_add_mode")
        ephemeral = cls._find_child(group_node, "ephemeral")

        participants: list[dict[str, Any]] = []
        for participant in cls._find_children(group_node, "participant"):
            participants.append(
                {
                    "id": participant.attrs.get("jid"),
                    "jid": participant.attrs.get("jid"),
                    "admin": participant.attrs.get("type"),
                    "phone_number": participant.attrs.get("phone_number"),
                    "lid": participant.attrs.get("lid"),
                }
            )

        size = cls._to_int(group_node.attrs.get("size")) or len(participants)

        return {
            "id": group_id,
            "notify": group_node.attrs.get("notify"),
            "subject_owner": group_node.attrs.get("s_o"),
            "subject_time": subject_time,
            "subject": group_node.attrs.get("subject", ""),
            "owner": group_node.attrs.get("creator"),
            "size": size,
            "creation": cls._to_int(group_node.attrs.get("creation")),
            "description": description,
            "desc_id": description_node.attrs.get("id") if description_node else None,
            "desc_owner": description_node.attrs.get("participant") if description_node else None,
            "desc_time": desc_time if desc_time > 0 else None,
            "linked_parent": cls._find_child(group_node, "linked_parent").attrs.get("jid")
            if cls._find_child(group_node, "linked_parent")
            else None,
            "restrict": cls._find_child(group_node, "locked") is not None,
            "announce": cls._find_child(group_node, "announcement") is not None,
            "is_community": cls._find_child(group_node, "parent") is not None,
            "is_community_announce": cls._find_child(group_node, "default_sub_group") is not None,
            "join_approval_mode": cls._find_child(group_node, "membership_approval_mode") is not None,
            "member_add_mode": cls._content_to_str(member_add_mode.content) == "all_member_add"
            if member_add_mode is not None
            else False,
            "ephemeral_duration": cls._to_int(ephemeral.attrs.get("expiration")) if ephemeral else None,
            "participants": participants,
        }

    @classmethod
    def _normalize_group_jid(cls, raw_id: str | None) -> str:
        value = raw_id or ""
        return value if value.endswith("@g.us") else f"{value}@g.us"

    @staticmethod
    def _content_to_str(content: object) -> str:
        if isinstance(content, (bytes, bytearray)):
            return bytes(content).decode("utf-8", errors="ignore")
        if isinstance(content, str):
            return content
        return ""

    @staticmethod
    def _to_int(value: str | None) -> int:
        if value is None:
            return 0
        try:
            return int(value)
        except ValueError:
            return 0

    @staticmethod
    def _children(node: BinaryNode | None) -> list[BinaryNode]:
        if node is None or not isinstance(node.content, list):
            return []
        return [child for child in node.content if isinstance(child, BinaryNode)]

    @classmethod
    def _find_child(cls, node: BinaryNode | None, tag: str) -> BinaryNode | None:
        for child in cls._children(node):
            if child.tag == tag:
                return child
        return None

    @classmethod
    def _find_children(cls, node: BinaryNode | None, tag: str) -> list[BinaryNode]:
        return [child for child in cls._children(node) if child.tag == tag]

    @classmethod
    def _extract_group_jid(cls, node: BinaryNode | None) -> str | None:
        if node is None:
            return None

        jid = node.attrs.get("jid") or node.attrs.get("id")
        if isinstance(jid, str) and jid:
            return cls._normalize_group_jid(jid)

        if isinstance(node.content, list):
            for child in node.content:
                found = cls._extract_group_jid(child)
                if found:
                    return found
        return None
