from waton.protocol.binary_node import BinaryNode
from waton.client.client import WAClient
from typing import Optional


_CHAT_MODIFY_ACTIONS: dict[str, tuple[str, dict[str, str]]] = {
    "archive": ("archive", {"value": "true"}),
    "unarchive": ("archive", {"value": "false"}),
    "pin": ("pin", {"value": "true"}),
    "unpin": ("pin", {"value": "false"}),
    "mute": ("mute", {"value": "true"}),
    "unmute": ("mute", {"value": "false"}),
    "read": ("mark", {"type": "read"}),
    "unread": ("mark", {"type": "unread"}),
}


class ChatsAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def send_presence_update(self, jid: str, presence: str) -> None:
        """
        Sends presence updates (e.g. typing, available) to a specific chat.
        presence: 'composing', 'paused', 'available', 'unavailable'
        """
        node = BinaryNode(
            tag="presence",
            attrs={"to": jid, "type": presence}
        )
        await self.client.send_node(node)

    async def presence_subscribe(self, jid: str) -> None:
        node = BinaryNode(tag="presence", attrs={"to": jid, "type": "subscribe"})
        await self.client.send_node(node)

    async def get_profile_picture(self, jid: str) -> Optional[str]:
        """Requests the profile picture URL for a JID."""
        query_node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "w:profile:picture"},
            content=[BinaryNode(tag="picture", attrs={"target": jid})]
        )
        res = await self.client.query(query_node)
        picture = self._find_child(res, "picture")
        return picture.attrs.get("url") if picture else None

    async def fetch_blocklist(self) -> list[str]:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "blocklist"},
            content=[BinaryNode(tag="list", attrs={})],
        )
        result = await self.client.query(node)
        list_node = self._find_child(result, "list")
        if not list_node:
            return []
        return [
            item.attrs["jid"]
            for item in self._find_children(list_node, "item")
            if "jid" in item.attrs
        ]

    async def fetch_privacy_settings(self) -> dict[str, str]:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "privacy"},
            content=[BinaryNode(tag="privacy", attrs={})],
        )
        result = await self.client.query(node)
        privacy = self._find_child(result, "privacy")
        if privacy is None:
            return {}

        settings: dict[str, str] = {}
        for category in self._find_children(privacy, "category"):
            name = category.attrs.get("name")
            value = category.attrs.get("value")
            if name and value:
                settings[name] = value
        return settings

    async def update_last_seen_privacy(self, value: str) -> None:
        await self._privacy_update("last", value)

    async def update_read_receipts_privacy(self, value: str) -> None:
        await self._privacy_update("readreceipts", value)

    async def _privacy_update(self, name: str, value: str) -> None:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "privacy"},
            content=[
                BinaryNode(
                    tag="privacy",
                    attrs={},
                    content=[BinaryNode(tag="category", attrs={"name": name, "value": value})],
                )
            ],
        )
        await self.client.query(node)

    async def update_profile_status(self, status: str) -> None:
        """Updates the current user's about/status text."""
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "status"},
            content=[BinaryNode(tag="status", attrs={}, content=status)]
        )
        await self.client.send_node(node)

    async def update_profile_name(self, name: str) -> None:
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "profile"},
            content=[BinaryNode(tag="profile", attrs={"name": name})],
        )
        await self.client.send_node(node)

    async def chat_modify(self, jid: str, action: str) -> None:
        """Modifies chat archive/mute/pin/read status via `w:chat` query."""
        normalized_action = action.strip().lower()
        action_spec = _CHAT_MODIFY_ACTIONS.get(normalized_action)
        if action_spec is None:
            raise ValueError(f"Unsupported chat modify action: {action}")

        op_tag, op_attrs = action_spec
        node = BinaryNode(
            tag="iq",
            attrs={"to": "s.whatsapp.net", "type": "set", "xmlns": "w:chat"},
            content=[
                BinaryNode(
                    tag="chat",
                    attrs={"jid": jid},
                    content=[BinaryNode(tag=op_tag, attrs=dict(op_attrs))],
                )
            ],
        )
        await self.client.query(node)

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
