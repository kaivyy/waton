from typing import Any
from dataclasses import dataclass

@dataclass
class ConnectionEvent:
    status: str  # "connecting", "open", "close"
    qr: str | None = None
    reason: Any | None = None

@dataclass
class MessagesUpsertEvent:
    messages: list[Any]
    type: str  # "append", "notify"

@dataclass
class MessageUpdateEvent:
    updates: list[dict]
