"""Protobuf access layer.

Uses generated WAProto bindings when available and falls back to a minimal shim
to keep high-level imports usable in dev environments.
"""

from __future__ import annotations

import json
from importlib import import_module
from dataclasses import dataclass, field
from types import SimpleNamespace

try:
    wa_pb2 = import_module(".WAProto_pb2", __name__)
except ModuleNotFoundError:

    @dataclass
    class _MessageKey:
        id: str = ""
        remoteJid: str = ""

    @dataclass
    class _ReactionMessage:
        key: _MessageKey = field(default_factory=_MessageKey)
        text: str = ""

    @dataclass
    class _ExtendedTextMessage:
        text: str = ""

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
                    "text": self.reactionMessage.text,
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
            self.reactionMessage.text = str(reaction.get("text", ""))

    wa_pb2 = SimpleNamespace(Message=_Message)


__all__ = ["wa_pb2"]
