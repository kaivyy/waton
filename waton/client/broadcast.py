"""WhatsApp Broadcast Status Distribution module."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from waton.core.jid import S_WHATSAPP_NET
from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from waton.client.client import WAClient


class BroadcastAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def get_status_privacy(self) -> dict[str, Any]:
        """Gets status privacy settings."""
        iq = BinaryNode(
            tag="iq",
            attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "status"},
            content=[BinaryNode(tag="privacy", attrs={})]
        )
        res = await self.client.query(iq)
        privacy = self._find_child(res, "privacy")
        
        result: dict[str, Any] = {"type": "contacts", "list": [], "is_default": True}
        if not privacy or not isinstance(privacy.content, list):
            return result

        for list_node in privacy.content:
            if not isinstance(list_node, BinaryNode) or list_node.tag != "list":
                continue
            
            result["type"] = list_node.attrs.get("type", "contacts")
            result["is_default"] = list_node.attrs.get("default") == "true"
            if isinstance(list_node.content, list):
                result["list"] = [
                    child.attrs["jid"]
                    for child in list_node.content
                    if isinstance(child, BinaryNode) and child.tag == "user" and "jid" in child.attrs
                ]
            if result["is_default"]:
                break

        return result

    async def get_status_recipients(self) -> list[str]:
        """Resolves recipient JIDs based on current privacy mode and contact list."""
        privacy = await self.get_status_privacy()
        mode = privacy.get("type", "contacts")
        if mode == "whitelist":
            return privacy.get("list", [])
        
        return []

    @classmethod
    def _find_child(cls, node: BinaryNode | None, tag: str) -> BinaryNode | None:
        if node is None or not isinstance(node.content, list):
            return None
        for child in node.content:
            if isinstance(child, BinaryNode) and child.tag == tag:
                return child
        return None
