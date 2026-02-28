from __future__ import annotations

import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_WA_SUFFIX = "@s.whatsapp.net"
_WA_ID_RE = re.compile(r"^\d{6,20}$")


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def normalize_wa_id(raw: str) -> str:
    candidate = (raw or "").strip()
    if candidate.endswith(_WA_SUFFIX):
        candidate = candidate[: -len(_WA_SUFFIX)]
    if candidate.startswith("+"):
        candidate = candidate[1:]
    if not _WA_ID_RE.fullmatch(candidate):
        raise ValueError("Invalid WhatsApp ID. Use digits only with optional '+' prefix.")
    return candidate


@dataclass(slots=True)
class DashboardEvent:
    kind: str
    source: str
    payload: dict[str, Any]
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "kind": self.kind,
            "source": self.source,
            "payload": self.payload,
        }


class DashboardState:
    def __init__(self, max_events: int = 300) -> None:
        self._max_events = max(1, int(max_events))
        self._events: list[DashboardEvent] = []
        self._lock = threading.Lock()

    def add_event(self, event: DashboardEvent) -> None:
        with self._lock:
            self._events.append(event)
            overflow = len(self._events) - self._max_events
            if overflow > 0:
                del self._events[:overflow]

    def list_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [event.to_dict() for event in self._events]
