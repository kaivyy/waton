"""High-level message context object."""

from __future__ import annotations

from dataclasses import dataclass

from waton.core.entities import Message
from waton.protocol.binary_node import BinaryNode


@dataclass
class Context:
    message: Message
    app: "App"

    @property
    def text(self) -> str | None:
        return self.message.text

    @property
    def from_jid(self) -> str:
        return self.message.from_jid

    @property
    def sender(self) -> str:
        return self.message.participant or self.message.from_jid

    async def reply(self, text: str) -> str:
        return await self.app.messages.send_text(self.from_jid, text)

    async def react(self, emoji: str) -> str:
        return await self.app.messages.send_reaction(self.from_jid, self.message.id, emoji)

    async def forward(self, to_jid: str) -> None:
        node = BinaryNode(
            tag="message",
            attrs={"to": to_jid, "type": "forward"},
            content=self.message.raw_node.content if self.message.raw_node else b"",
        )
        await self.app.client.send_node(node)

    async def delete(self) -> None:
        node = BinaryNode(
            tag="protocol",
            attrs={"type": "revoke", "to": self.from_jid, "id": self.message.id},
        )
        await self.app.client.send_node(node)

