"""High-level message context object."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from waton.app.app import App
    from waton.core.entities import Message


@dataclass
class Context:
    message: Message
    app: App
    trace_id: str = ""
    trace_message_id: str = ""

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
        try:
            return await self.app.messages.send_text(
                self.from_jid,
                text,
                quoted=self.message,
            )
        except TypeError:
            return await self.app.messages.send_text(self.from_jid, text)

    async def react(self, emoji: str | None) -> str:
        return await self.app.messages.send_reaction(
            self.from_jid,
            self.message.id,
            emoji or "",
            participant=self.message.participant,
        )

    async def forward(self, to_jid: str) -> None:
        node = BinaryNode(
            tag="message",
            attrs={"to": to_jid, "type": "forward"},
            content=self.message.raw_node.content if self.message.raw_node else b"",
        )
        await self.app.client.send_node(node)

    async def delete(self) -> str:
        me_jid = (
            self.app.client.creds.me["id"]
            if self.app.client.creds and self.app.client.creds.me
            else ""
        )
        from_me = (self.message.participant or self.message.from_jid) == me_jid
        return await self.app.messages.send_delete(
            self.from_jid,
            self.message.id,
            participant=self.message.participant,
            from_me=from_me,
        )

