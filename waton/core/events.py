from dataclasses import dataclass
from typing import Any


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
    updates: list[dict[str, Any]]
