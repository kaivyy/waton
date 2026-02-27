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
            metadata.append(BinaryNode(tag="picture", attrs={"source": "inline"}))

        node = BinaryNode(
            tag="iq",
            attrs={"to": "@newsletter", "type": "set", "xmlns": "newsletter", "id": create_id},
            content=[BinaryNode(tag="create", attrs={}, content=metadata)],
        )
        res = await self.client.query(node)
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

        return {
            "jid": self._normalize_newsletter_jid(newsletter.attrs.get("jid") or jid),
            "name": self._content_to_str(name_node.content) if name_node else "",
            "description": self._content_to_str(description_node.content) if description_node else "",
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
        return [child for child in node.content if isinstance(child, BinaryNode)]

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
