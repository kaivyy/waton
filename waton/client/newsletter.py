import os
from typing import Any

from waton.client.client import WAClient
from waton.protocol.binary_node import BinaryNode


class NewsletterAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def create_newsletter(
        self,
        name: str,
        description: str = "",
        picture_bytes: bytes | None = None,
    ) -> str:
        """Creates a WhatsApp channel (newsletter) and returns its JID."""
        create_id = os.urandom(6).hex()

        metadata: list[BinaryNode] = [
            BinaryNode(tag="name", attrs={}, content=name),
            BinaryNode(tag="description", attrs={}, content=description),
        ]
        if picture_bytes:
            metadata.append(BinaryNode(tag="picture", attrs={"source": "inline"}, content=picture_bytes))

        node = BinaryNode(
            tag="iq",
            attrs={"to": "@newsletter", "type": "set", "xmlns": "newsletter", "id": create_id},
            content=[BinaryNode(tag="create", attrs={}, content=metadata)],
        )
        res = await self.client.query(node)
        if res.attrs.get("type") == "error":
            err = self._find_child(res, "error")
            code = err.attrs.get("code") if err else "unknown"
            text = err.attrs.get("text") if err else ""
            raise ValueError(f"create_newsletter error {code}: {text}")
        jid = self._extract_newsletter_jid(res)
        if not jid:
            raise ValueError("create_newsletter response missing newsletter jid")
        return jid

    async def newsletter_metadata(self, jid: str) -> dict[str, Any]:
        result = await self._newsletter_query(jid, "get", [BinaryNode(tag="metadata", attrs={})])
        newsletter = self._find_child(result, "newsletter")
        if newsletter is None:
            raise ValueError("newsletter metadata response missing newsletter node")

        name_node = self._find_child(newsletter, "name")
        description_node = self._find_child(newsletter, "description")
        subscribers_node = self._find_child(newsletter, "subscribers")
        verification_node = self._find_child(newsletter, "verification")
        picture_node = self._find_child(newsletter, "picture")
        invite_node = self._find_child(newsletter, "invite")
        mute_node = self._find_child(newsletter, "mute")

        return {
            "jid": self._normalize_newsletter_jid(newsletter.attrs.get("jid") or jid),
            "name": self._content_to_str(name_node.content) if name_node else "",
            "description": self._content_to_str(description_node.content) if description_node else "",
            "creation_time": newsletter.attrs.get("creation_time") or newsletter.attrs.get("t"),
            "subscribers": self._content_to_str(subscribers_node.content) if subscribers_node else None,
            "verification": verification_node.attrs.get("state") if verification_node else None,
            "picture": (picture_node.attrs.get("direct_path") or picture_node.attrs.get("url")) if picture_node else None,
            "invite": self._content_to_str(invite_node.content) if invite_node else None,
            "mute": mute_node.attrs.get("state") if mute_node else None,
        }

    async def follow_newsletter(self, jid: str) -> None:
        """Follows a WhatsApp channel."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": jid, "type": "set", "xmlns": "newsletter"},
            content=[BinaryNode(tag="follow", attrs={})],
        )
        await self.client.send_node(node)

    async def unfollow_newsletter(self, jid: str) -> None:
        node = BinaryNode(
            tag="iq",
            attrs={"to": jid, "type": "set", "xmlns": "newsletter"},
            content=[BinaryNode(tag="unfollow", attrs={})],
        )
        await self.client.send_node(node)

    async def mute_newsletter(self, jid: str, mute: bool = True) -> None:
        """Mutes or unmutes a channel."""
        action = "mute" if mute else "unmute"
        node = BinaryNode(
            tag="iq",
            attrs={"to": jid, "type": "set", "xmlns": "newsletter"},
            content=[BinaryNode(tag=action, attrs={})],
        )
        await self.client.send_node(node)

    async def newsletter_update_name(self, jid: str, name: str) -> None:
        await self._newsletter_query(
            jid,
            "set",
            [
                BinaryNode(
                    tag="update",
                    attrs={},
                    content=[BinaryNode(tag="name", attrs={}, content=name)],
                )
            ],
        )

    async def newsletter_update_description(self, jid: str, description: str) -> None:
        await self._newsletter_query(
            jid,
            "set",
            [
                BinaryNode(
                    tag="update",
                    attrs={},
                    content=[BinaryNode(tag="description", attrs={}, content=description)],
                )
            ],
        )

    async def newsletter_update_picture(self, jid: str, picture_bytes: bytes) -> BinaryNode:
        """Updates channel profile picture."""
        return await self._newsletter_query(
            jid,
            "set",
            [
                BinaryNode(
                    tag="update",
                    attrs={},
                    content=[BinaryNode(tag="picture", attrs={}, content=picture_bytes)],
                )
            ],
        )

    async def newsletter_remove_picture(self, jid: str) -> BinaryNode:
        """Removes channel profile picture."""
        return await self._newsletter_query(
            jid,
            "set",
            [
                BinaryNode(
                    tag="update",
                    attrs={},
                    content=[BinaryNode(tag="picture", attrs={"delete": "true"})],
                )
            ],
        )

    async def newsletter_delete(self, jid: str) -> BinaryNode:
        """Deletes a newsletter channel."""
        return await self._newsletter_query(
            jid,
            "set",
            [BinaryNode(tag="delete", attrs={})],
        )

    async def newsletter_change_owner(self, jid: str, new_owner_jid: str) -> BinaryNode:
        """Transfers channel ownership to another user."""
        return await self._newsletter_query(
            jid,
            "set",
            [BinaryNode(tag="change_owner", attrs={"user": new_owner_jid})],
        )

    async def newsletter_demote(self, jid: str, user_jid: str) -> BinaryNode:
        """Demotes an admin in a newsletter channel."""
        return await self._newsletter_query(
            jid,
            "set",
            [BinaryNode(tag="demote", attrs={"user": user_jid})],
        )

    async def newsletter_mark_viewed(self, jid: str, server_ids: list[str]) -> None:
        """Marks channel messages as viewed with view receipt."""
        items = [BinaryNode(tag="item", attrs={"server_id": str(s_id)}) for s_id in server_ids]
        list_node = BinaryNode(tag="list", attrs={}, content=items)
        receipt_node = BinaryNode(
            tag="receipt",
            attrs={"to": jid, "type": "view", "id": self._generate_message_id()},
            content=[list_node],
        )
        await self.client.send_node(receipt_node)

    async def newsletter_react_message(self, jid: str, server_id: str, reaction: str | None = None) -> None:
        attrs: dict[str, str] = {
            "to": jid,
            "type": "reaction",
            "server_id": server_id,
            "id": self._generate_message_id(),
        }
        if reaction is None:
            attrs["edit"] = "7"

        await self.client.query(
            BinaryNode(
                tag="message",
                attrs=attrs,
                content=[
                    BinaryNode(
                        tag="reaction",
                        attrs={"code": reaction} if reaction is not None else {},
                    )
                ],
            )
        )

    async def newsletter_fetch_messages(
        self,
        jid: str,
        count: int,
        since: int | None = None,
        after: int | None = None,
    ) -> BinaryNode:
        attrs = {"count": str(count)}
        if since is not None:
            attrs["since"] = str(since)
        if after is not None:
            attrs["after"] = str(after)

        return await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={
                    "id": self._generate_message_id(),
                    "type": "get",
                    "xmlns": "newsletter",
                    "to": jid,
                },
                content=[BinaryNode(tag="message_updates", attrs=attrs)],
            )
        )

    async def subscribe_newsletter_updates(self, jid: str) -> dict[str, str] | None:
        result = await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={
                    "id": self._generate_message_id(),
                    "type": "set",
                    "xmlns": "newsletter",
                    "to": jid,
                },
                content=[BinaryNode(tag="live_updates", attrs={}, content=[])],
            )
        )
        live_updates = self._find_child(result, "live_updates")
        duration = live_updates.attrs.get("duration") if live_updates else None
        return {"duration": duration} if duration else None

    async def unmute_newsletter(self, jid: str) -> None:
        """Unmutes a channel."""
        await self.mute_newsletter(jid, mute=False)

    async def newsletter_subscribers(self, jid: str) -> list[dict[str, Any]]:
        """Fetches subscriber list/count for a newsletter via MEX GraphQL."""
        mex = getattr(self.client, "mex", None)
        if not mex:
            return []
        from waton.client.mex import QueryIds

        clean_id = jid.split("@")[0]
        res = await mex.execute_wmex_query(
            QueryIds.SUBSCRIBERS,
            {"newsletter_id": clean_id},
            data_path="xwa2_newsletter_subscribers",
        )
        return res if isinstance(res, list) else []

    async def newsletter_admin_count(self, jid: str) -> int:
        """Fetches total admin count for a newsletter via MEX GraphQL."""
        mex = getattr(self.client, "mex", None)
        if not mex:
            return 0
        from waton.client.mex import QueryIds

        clean_id = jid.split("@")[0]
        res = await mex.execute_wmex_query(
            QueryIds.ADMIN_COUNT,
            {"newsletter_id": clean_id},
        )
        if isinstance(res, dict) and "admin_count" in res:
            return int(res["admin_count"])
        return 0

    async def get_subscribed_newsletters(self) -> list[dict[str, Any]]:
        """Gets all channels the current user is subscribed to."""
        from waton.core.jid import S_WHATSAPP_NET

        iq = BinaryNode(
            tag="iq",
            attrs={
                "to": S_WHATSAPP_NET,
                "type": "get",
                "xmlns": "newsletter",
                "id": self._generate_message_id(),
            },
            content=[BinaryNode(tag="subscribed", attrs={})],
        )
        res = await self.client.query(iq)
        sub_node = self._find_child(res, "subscribed")
        channels: list[dict[str, Any]] = []
        if sub_node and isinstance(sub_node.content, list):
            for child in sub_node.content:
                if isinstance(child, BinaryNode) and child.tag == "newsletter":
                    channels.append(dict(child.attrs))
        return channels

    async def get_newsletter_info_with_invite(self, invite_key: str) -> dict[str, Any] | None:
        """Fetches public channel metadata using invite code/key."""
        from waton.core.jid import S_WHATSAPP_NET

        clean_code = invite_key.split("/")[-1]
        iq = BinaryNode(
            tag="iq",
            attrs={
                "to": S_WHATSAPP_NET,
                "type": "get",
                "xmlns": "newsletter",
                "id": self._generate_message_id(),
            },
            content=[BinaryNode(tag="newsletter", attrs={"key": clean_code})],
        )
        res = await self.client.query(iq)
        node = self._find_child(res, "newsletter")
        if not node:
            return None
        return dict(node.attrs)

    async def accept_tos_notice(self) -> None:
        """Accepts WhatsApp Channels Terms of Service notice."""
        from waton.core.jid import S_WHATSAPP_NET

        iq = BinaryNode(
            tag="iq",
            attrs={
                "to": S_WHATSAPP_NET,
                "type": "set",
                "xmlns": "tos",
                "id": self._generate_message_id(),
            },
            content=[BinaryNode(tag="notice", attrs={"id": "20601218", "stage": "5"})],
        )
        await self.client.send_node(iq)

    async def _newsletter_query(self, jid: str, request_type: str, content: list[BinaryNode]) -> BinaryNode:
        query_id = os.urandom(6).hex()
        return await self.client.query(
            BinaryNode(
                tag="iq",
                attrs={"to": jid, "type": request_type, "xmlns": "newsletter", "id": query_id},
                content=content,
            )
        )

    @staticmethod
    def _content_to_str(content: object) -> str:
        if isinstance(content, (bytes, bytearray)):
            return bytes(content).decode("utf-8", errors="ignore")
        if isinstance(content, str):
            return content
        return ""

    @staticmethod
    def _children(node: BinaryNode | None) -> list[BinaryNode]:
        if node is None or not isinstance(node.content, list):
            return []
        return list(node.content)

    @classmethod
    def _find_child(cls, node: BinaryNode | None, tag: str) -> BinaryNode | None:
        for child in cls._children(node):
            if child.tag == tag:
                return child
        return None

    @staticmethod
    def _normalize_newsletter_jid(value: str) -> str:
        return value if value.endswith("@newsletter") else f"{value}@newsletter"

    @staticmethod
    def _generate_message_id() -> str:
        return os.urandom(6).hex()

    @classmethod
    def _extract_newsletter_jid(cls, node: BinaryNode | None) -> str | None:
        if node is None:
            return None

        jid = node.attrs.get("jid") or node.attrs.get("id")
        if isinstance(jid, str) and jid:
            return cls._normalize_newsletter_jid(jid)

        if isinstance(node.content, list):
            for child in node.content:
                found = cls._extract_newsletter_jid(child)
                if found:
                    return found
        return None
