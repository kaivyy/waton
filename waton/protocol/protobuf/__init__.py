# ruff: noqa: N802, N815

"""Protobuf access layer.

Uses generated WAProto bindings when available and falls back to a minimal shim
to keep high-level imports usable in dev environments.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import import_module
from types import SimpleNamespace

try:
    wa_pb2 = import_module(".WAProto_pb2", __name__)
except ModuleNotFoundError:

    @dataclass
    class _MessageKey:
        id: str = ""
        remoteJid: str = ""
        participant: str = ""
        fromMe: bool = False

    @dataclass
    class _ReactionMessage:
        key: _MessageKey = field(default_factory=_MessageKey)
        text: str = ""
        groupingKey: str = ""
        senderTimestampMs: int = 0

    @dataclass
    class _ExtendedTextMessage:
        text: str = ""
        contextInfo: bytes = b""

    class _Message:
        def __init__(self) -> None:
            self.conversation = ""
            self.extendedTextMessage = _ExtendedTextMessage()
            self.reactionMessage = _ReactionMessage()

        def SerializeToString(self) -> bytes:
            payload = {
                "conversation": self.conversation,
                "extended_text": self.extendedTextMessage.text,
                "reaction": {
                    "id": self.reactionMessage.key.id,
                    "remote_jid": self.reactionMessage.key.remoteJid,
                    "participant": self.reactionMessage.key.participant,
                    "from_me": self.reactionMessage.key.fromMe,
                    "text": self.reactionMessage.text,
                    "sender_timestamp_ms": self.reactionMessage.senderTimestampMs,
                },
            }
            return json.dumps(payload, separators=(",", ":")).encode("utf-8")

        def ParseFromString(self, data: bytes) -> None:
            try:
                payload = json.loads(data.decode("utf-8"))
            except Exception:
                self.conversation = data.decode("utf-8", errors="ignore")
                return

            self.conversation = str(payload.get("conversation", ""))
            self.extendedTextMessage.text = str(payload.get("extended_text", ""))
            reaction = payload.get("reaction", {})
            self.reactionMessage.key.id = str(reaction.get("id", ""))
            self.reactionMessage.key.remoteJid = str(reaction.get("remote_jid", ""))
            self.reactionMessage.key.participant = str(reaction.get("participant", ""))
            self.reactionMessage.key.fromMe = bool(reaction.get("from_me", False))
            self.reactionMessage.text = str(reaction.get("text", ""))
            self.reactionMessage.senderTimestampMs = int(reaction.get("sender_timestamp_ms", 0))

    wa_pb2 = SimpleNamespace(Message=_Message)


__all__ = ["wa_pb2"]
