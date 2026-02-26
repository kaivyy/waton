"""Small in-memory event buffer with replay support."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from time import time
from typing import Any


@dataclass
class BufferedEvent:
    event: str
    payload: Any
    timestamp: float


class EventBuffer:
    def __init__(self, max_events: int = 1000) -> None:
        self._events: deque[BufferedEvent] = deque(maxlen=max_events)

    def push(self, event: str, payload: Any) -> None:
        self._events.append(BufferedEvent(event=event, payload=payload, timestamp=time()))

    def recent(self, event: str | None = None) -> list[BufferedEvent]:
        if event is None:
            return list(self._events)
        return [e for e in self._events if e.event == event]

    def __iter__(self) -> Iterator[BufferedEvent]:
        return iter(self._events)
