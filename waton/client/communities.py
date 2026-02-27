import os
from typing import Any

from waton.client.client import WAClient
from waton.protocol.binary_node import BinaryNode


class CommunitiesAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def community_metadata(self, jid: str) -> dict[str, Any]:
        result = await self._community_query(
            jid,
            "get",
            [BinaryNode(tag="query", attrs={"request": "interactive"})],
        )
        community = self._find_child(result, "community")
        if community is None:
            raise ValueError("community metadata response missing community node")
        return self._parse_community_node(community)

    async def community_fetch_all_participating(self) -> dict[str, dict[str, Any]]:
        result = await self._community_query(
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
        communities_node = self._find_child(result, "communities")
        if communities_node is None:
            return {}

        data: dict[str, dict[str, Any]] = {}
        for node in self._find_children(communities_node, "community"):
            parsed = self._parse_community_node(node)
            data[parsed["id"]] = parsed
        return data

    async def create_community(self, name: str, description: str = "") -> str:
        """Creates a WhatsApp Community and returns its JID."""
        create_id = os.urandom(6).hex()

        create_node = BinaryNode(
            tag="create",
            attrs={"subject": name},
            content=[BinaryNode(tag="description", attrs={}, content=description)],
        )

        node = BinaryNode(
            tag="iq",
            attrs={"to": "@g.us", "type": "set", "xmlns": "w:g2", "id": create_id},
            content=[create_node],
        )
        res = await self.client.query(node)
        jid = self._extract_community_jid(res)
        if not jid:
            raise ValueError("create_community response missing community jid")
        return jid

    async def community_create_group(
        self,
        subject: str,
        participants: list[str],
        parent_community_jid: str,
    ) -> str:
        key = os.urandom(6).hex()
        result = await self._community_query(
            "@g.us",
            "set",
            [
                BinaryNode(
                    tag="create",
                    attrs={"subject": subject, "key": key},
                    content=[
                        *[BinaryNode(tag="participant", attrs={"jid": value}) for value in participants],
                        BinaryNode(tag="linked_parent", attrs={"jid": parent_community_jid}),
                    ],
                )
            ],
        )
        jid = self._extract_community_jid(result)
        if not jid:
            raise ValueError("community_create_group response missing linked group jid")
        return jid

    async def community_update_subject(self, jid: str, subject: str) -> None:
        await self._community_query(jid, "set", [BinaryNode(tag="subject", attrs={}, content=subject.encode("utf-8"))])

    async def community_update_description(self, jid: str, description: str | None) -> None:
        attrs = {"id": os.urandom(6).hex()} if description else {"delete": "true"}
        content = [BinaryNode(tag="body", attrs={}, content=description.encode("utf-8"))] if description else None
        await self._community_query(jid, "set", [BinaryNode(tag="description", attrs=attrs, content=content)])

    async def community_setting_update(self, jid: str, setting: str) -> None:
        await self._community_query(jid, "set", [BinaryNode(tag=setting, attrs={})])

    async def community_toggle_ephemeral(self, jid: str, ephemeral_expiration: int) -> None:
        content = (
            BinaryNode(tag="ephemeral", attrs={"expiration": str(ephemeral_expiration)})
            if ephemeral_expiration
            else BinaryNode(tag="not_ephemeral", attrs={})
        )
        await self._community_query(jid, "set", [content])

    async def community_member_add_mode(self, jid: str, mode: str) -> None:
        await self._community_query(jid, "set", [BinaryNode(tag="member_add_mode", attrs={}, content=mode)])

    async def community_join_approval_mode(self, jid: str, mode: str) -> None:
        await self._community_query(
            jid,
            "set",
            [
                BinaryNode(
                    tag="membership_approval_mode",
                    attrs={},
                    content=[BinaryNode(tag="community_join", attrs={"state": mode})],
                )
            ],
        )

    async def community_request_participants_list(self, jid: str) -> list[dict[str, str]]:
        result = await self._community_query(jid, "get", [BinaryNode(tag="membership_approval_requests", attrs={})])
        requests_node = self._find_child(result, "membership_approval_requests")
        return [dict(node.attrs) for node in self._find_children(requests_node, "membership_approval_request")]

    async def community_request_participants_update(
        self,
        jid: str,
        participants: list[str],
        action: str,
    ) -> list[dict[str, str]]:
        result = await self._community_query(
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

    async def community_participants_update(
        self,
        jid: str,
        participants: list[str],
        action: str,
    ) -> list[dict[str, Any]]:
        attrs = {"linked_groups": "true"} if action == "remove" else {}
        result = await self._community_query(
            jid,
            "set",
            [
                BinaryNode(
                    tag=action,
                    attrs=attrs,
                    content=[BinaryNode(tag="participant", attrs={"jid": value}) for value in participants],
                )
            ],
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

    async def community_invite_code(self, jid: str) -> str | None:
        result = await self._community_query(jid, "get", [BinaryNode(tag="invite", attrs={})])
        invite = self._find_child(result, "invite")
        return invite.attrs.get("code") if invite else None

    async def community_revoke_invite(self, jid: str) -> str | None:
        result = await self._community_query(jid, "set", [BinaryNode(tag="invite", attrs={})])
        invite = self._find_child(result, "invite")
        return invite.attrs.get("code") if invite else None

    async def community_accept_invite(self, code: str) -> str | None:
        result = await self._community_query("@g.us", "set", [BinaryNode(tag="invite", attrs={"code": code})])
        community = self._find_child(result, "community")
        if not community:
            return None
        community_jid = community.attrs.get("jid") or community.attrs.get("id")
        if not isinstance(community_jid, str):
            return None
        return self._normalize_community_jid(community_jid)

    async def community_get_invite_info(self, code: str) -> dict[str, Any]:
        result = await self._community_query("@g.us", "get", [BinaryNode(tag="invite", attrs={"code": code})])
        community_node = self._find_child(result, "community")
        if community_node is None:
            raise ValueError("invite info response missing community node")
        return self._parse_community_node(community_node)

    async def community_link_group(self, group_jid: str, parent_community_jid: str) -> None:
        await self._community_query(
            parent_community_jid,
            "set",
            [
                BinaryNode(
                    tag="links",
                    attrs={},
                    content=[
                        BinaryNode(
                            tag="link",
                            attrs={"link_type": "sub_group"},
                            content=[BinaryNode(tag="group", attrs={"jid": group_jid})],
                        )
                    ],
                )
            ],
        )

    async def community_unlink_group(self, group_jid: str, parent_community_jid: str) -> None:
        await self._community_query(
            parent_community_jid,
            "set",
            [
                BinaryNode(
                    tag="unlink",
                    attrs={"unlink_type": "sub_group"},
                    content=[BinaryNode(tag="group", attrs={"jid": group_jid})],
                )
            ],
        )

    async def community_fetch_linked_groups(self, jid: str) -> dict[str, Any]:
        try:
            metadata = await self.community_metadata(jid)
        except ValueError:
            metadata = {}
        linked_parent = metadata.get("linked_parent")
        is_community = not isinstance(linked_parent, str) or not linked_parent
        community_jid = jid if is_community else str(linked_parent)

        result = await self._community_query(community_jid, "get", [BinaryNode(tag="sub_groups", attrs={})])
        sub_groups_node = self._find_child(result, "sub_groups")

        linked_groups: list[dict[str, Any]] = []
        for node in self._find_children(sub_groups_node, "group"):
            linked_groups.append(
                {
                    "id": self._normalize_community_jid(node.attrs.get("id")),
                    "subject": node.attrs.get("subject", ""),
                    "creation": self._to_int(node.attrs.get("creation")),
                    "owner": node.attrs.get("creator"),
                    "size": self._to_int(node.attrs.get("size")),
                }
            )
        return {
            "community_jid": community_jid,
            "is_community": is_community,
            "linked_groups": linked_groups,
        }

    async def link_groups(self, community_jid: str, group_jids: list[str]) -> None:
        """Links existing WhatsApp groups to a parent community."""
        links = [BinaryNode(tag="group", attrs={"jid": jid}) for jid in group_jids]

        node = BinaryNode(
            tag="iq",
            attrs={"to": community_jid, "type": "set", "xmlns": "w:g2"},
            content=[BinaryNode(tag="links", attrs={}, content=links)],
        )
        await self.client.send_node(node)

    async def deactivate_community(self, community_jid: str) -> None:
        """Deactivates a WhatsApp community."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": community_jid, "type": "set", "xmlns": "w:g2"},
            content=[BinaryNode(tag="deactivate", attrs={})],
        )
        await self.client.send_node(node)

    async def _community_query(self, jid: str, request_type: str, content: list[BinaryNode]) -> BinaryNode:
        query_id = os.urandom(6).hex()
        return await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={"to": jid, "type": request_type, "xmlns": "w:g2", "id": query_id},
                content=content,
            )
        )

    @classmethod
    def _parse_community_node(cls, community_node: BinaryNode) -> dict[str, Any]:
        community_id = cls._normalize_community_jid(community_node.attrs.get("id"))
        description_node = cls._find_child(community_node, "description")
        body_node = cls._find_child(description_node, "body") if description_node else None
        description = cls._content_to_str(body_node.content) if body_node else None
        desc_time = cls._to_int(description_node.attrs.get("t")) if description_node else 0
        subject_time = cls._to_int(community_node.attrs.get("s_t"))
        member_add_mode = cls._find_child(community_node, "member_add_mode")
        ephemeral = cls._find_child(community_node, "ephemeral")

        participants: list[dict[str, Any]] = []
        for participant in cls._find_children(community_node, "participant"):
            participants.append(
                {
                    "jid": participant.attrs.get("jid"),
                    "id": participant.attrs.get("jid"),
                    "admin": participant.attrs.get("type"),
                }
            )

        size = cls._to_int(community_node.attrs.get("size")) or len(participants)

        return {
            "id": community_id,
            "subject": community_node.attrs.get("subject", ""),
            "creation": cls._to_int(community_node.attrs.get("creation")),
            "description": description,
            "desc_id": description_node.attrs.get("id") if description_node else None,
            "desc_owner": description_node.attrs.get("participant") if description_node else None,
            "desc_time": desc_time if desc_time > 0 else None,
            "subject_owner": community_node.attrs.get("s_o"),
            "subject_time": subject_time,
            "owner": community_node.attrs.get("creator"),
            "size": size,
            "linked_parent": cls._find_child(community_node, "linked_parent").attrs.get("jid")
            if cls._find_child(community_node, "linked_parent")
            else None,
            "restrict": cls._find_child(community_node, "locked") is not None,
            "announce": cls._find_child(community_node, "announcement") is not None,
            "is_community": cls._find_child(community_node, "parent") is not None,
            "is_community_announce": cls._find_child(community_node, "default_sub_community") is not None,
            "join_approval_mode": cls._find_child(community_node, "membership_approval_mode") is not None,
            "member_add_mode": cls._content_to_str(member_add_mode.content) == "all_member_add"
            if member_add_mode is not None
            else False,
            "ephemeral_duration": cls._to_int(ephemeral.attrs.get("expiration")) if ephemeral else None,
            "participants": participants,
        }

    @classmethod
    def _normalize_community_jid(cls, raw_id: str | None) -> str:
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
    def _extract_community_jid(cls, node: BinaryNode | None) -> str | None:
        if node is None:
            return None

        jid = node.attrs.get("jid") or node.attrs.get("id")
        if isinstance(jid, str) and jid:
            return cls._normalize_community_jid(jid)

        if isinstance(node.content, list):
            for child in node.content:
                found = cls._extract_community_jid(child)
                if found:
                    return found
        return None
