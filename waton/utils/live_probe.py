"""Helpers for live connection probing in integration tests/examples."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


@dataclass
class AckObservation:
    message_id: str
    remote_jid: str | None
    status: str
    error: str | None
    attrs: dict[str, Any]


class LiveProbe:
    """Collects live connection/ack signals and provides async wait helpers."""

    def __init__(self) -> None:
        self._open_event = asyncio.Event()
        self._close_event = asyncio.Event()
        self._ack_condition = asyncio.Condition()
        self._ack_by_id: dict[str, list[AckObservation]] = {}
        self.last_disconnect: Exception | None = None

    async def handle_connection_update(self, event: object) -> None:
        status = getattr(event, "status", None)
        if status == "open":
            self._open_event.set()
            self._close_event.clear()
        elif status == "close":
            self._close_event.set()
            self._open_event.clear()

    async def handle_message_node(self, node: object) -> None:
        tag = getattr(node, "tag", None)
        attrs = getattr(node, "attrs", None)
        if tag != "ack" or not isinstance(attrs, dict):
            return
        if attrs.get("class") != "message":
            return

        message_id = str(attrs.get("id", ""))
        if not message_id:
            return

        error = attrs.get("error")
        observation = AckObservation(
            message_id=message_id,
            remote_jid=attrs.get("from") or attrs.get("to"),
            status="error" if error else "ok",
            error=str(error) if error is not None else None,
            attrs=dict(attrs),
        )
        await self._record_ack(observation)

    async def handle_event(self, event: dict[str, Any]) -> None:
        if event.get("type") != "messages.bad_ack":
            return
        bad_ack = event.get("bad_ack")
        if not isinstance(bad_ack, dict):
            return

        message_id = bad_ack.get("message_id")
        if not isinstance(message_id, str) or not message_id:
            return

        error_raw = bad_ack.get("error")
        observation = AckObservation(
            message_id=message_id,
            remote_jid=bad_ack.get("remote_jid"),
            status="error",
            error=str(error_raw) if error_raw is not None else "unknown",
            attrs=dict(bad_ack),
        )
        await self._record_ack(observation)

    async def handle_disconnect(self, exc: Exception) -> None:
        self.last_disconnect = exc
        self._close_event.set()
        self._open_event.clear()

    async def wait_open(self, timeout: float) -> None:
        await asyncio.wait_for(self._open_event.wait(), timeout=timeout)

    async def wait_close(self, timeout: float) -> None:
        await asyncio.wait_for(self._close_event.wait(), timeout=timeout)

    async def wait_for_message_ack(self, message_id: str, timeout: float) -> AckObservation:
        async def _wait() -> AckObservation:
            while True:
                async with self._ack_condition:
                    existing = self._ack_by_id.get(message_id)
                    if existing:
                        return existing.pop(0)
                    await self._ack_condition.wait()

        return await asyncio.wait_for(_wait(), timeout=timeout)

    async def _record_ack(self, observation: AckObservation) -> None:
        async with self._ack_condition:
            self._ack_by_id.setdefault(observation.message_id, []).append(observation)
            self._ack_condition.notify_all()
