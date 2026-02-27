"""Presence API helpers."""

from waton.client.client import WAClient
from waton.protocol.binary_node import BinaryNode


class PresenceAPI:
    def __init__(self, client: WAClient) -> None:
        self.client = client

    async def send_presence(self, jid: str, presence: str) -> None:
        node = BinaryNode(tag="presence", attrs={"to": jid, "type": presence})
        await self.client.send_node(node)

    async def send_available(self, jid: str) -> None:
        await self.send_presence(jid, "available")

    async def send_unavailable(self, jid: str) -> None:
        await self.send_presence(jid, "unavailable")

    async def send_composing(self, jid: str) -> None:
        await self.send_presence(jid, "composing")

    async def send_paused(self, jid: str) -> None:
        await self.send_presence(jid, "paused")
