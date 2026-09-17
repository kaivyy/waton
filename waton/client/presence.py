from __future__ import annotations

from waton.client.client import WAClient
from waton.core.jid import jid_decode
from waton.protocol.binary_node import BinaryNode


class PresenceAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def send_presence(self, jid: str | None = None, presence: str = "available") -> None:
        attrs: dict[str, str] = {"type": presence}
        if jid:
            attrs["to"] = jid
        if hasattr(self.client, "creds") and self.client.creds and self.client.creds.me:
            name = self.client.creds.me.get("name")
            if name:
                attrs["name"] = name.replace("@", "")
        node = BinaryNode(tag="presence", attrs=attrs)
        await self.client.send_node(node)

    async def send_available(self, jid: str | None = None) -> None:
        await self.send_presence(jid, "available")

    async def send_unavailable(self, jid: str | None = None) -> None:
        await self.send_presence(jid, "unavailable")

    async def send_composing(self, jid: str) -> None:
        await self.send_presence(jid, "composing")

    async def send_paused(self, jid: str) -> None:
        await self.send_presence(jid, "paused")

    async def send_chat_presence(self, jid: str, state: str = "composing", media: str | None = None) -> None:
        """Sends chatstate typing/recording status to a conversation."""
        attrs: dict[str, str] = {"to": jid}
        me = getattr(self.client, "creds", None) and getattr(self.client.creds, "me", None)
        if me:
            decoded = jid_decode(jid) if jid else None
            is_lid = decoded is not None and decoded.server == "lid"
            from_jid = me.get("lid") if (is_lid and me.get("lid")) else me.get("id")
            if from_jid:
                attrs["from"] = from_jid

        child_attrs = {"media": media} if media else {}
        node = BinaryNode(
            tag="chatstate",
            attrs=attrs,
            content=[BinaryNode(tag=state, attrs=child_attrs)],
        )
        await self.client.send_node(node)

    async def send_chat_composing(self, jid: str, media: str | None = None) -> None:
        await self.send_chat_presence(jid, "composing", media=media)

    async def send_chat_recording(self, jid: str) -> None:
        await self.send_chat_presence(jid, "composing", media="audio")

    async def send_chat_paused(self, jid: str) -> None:
        await self.send_chat_presence(jid, "paused")

    async def presence_subscribe(self, jid: str) -> None:
        """Sends presence subscription request, attaching TC token if available."""
        content = None
        tc_mgr = getattr(self.client, "tc_token_manager", None)
        if tc_mgr is not None:
            token_data = tc_mgr.get_token(jid)
            if token_data:
                from waton.utils.tc_token import build_tc_token_node

                content = [build_tc_token_node(token_data["token"], token_data["timestamp"])]

        msg_id_fn = getattr(self.client, "generate_message_tag", None)
        msg_id = msg_id_fn() if callable(msg_id_fn) else None
        attrs: dict[str, str] = {"to": jid, "type": "subscribe"}
        if msg_id:
            attrs["id"] = msg_id

        node = BinaryNode(tag="presence", attrs=attrs, content=content)
        await self.client.send_node(node)

