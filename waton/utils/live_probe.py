"""Helpers for live connection probing in integration tests/examples."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Mapping


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

        attrs_map = cast("Mapping[str, object]", attrs)
        if attrs_map.get("class") != "message":
            return

        raw_message_id = attrs_map.get("id")
        message_id = raw_message_id if isinstance(raw_message_id, str) else ""
        if not message_id:
            return

        error = attrs_map.get("error")
        remote_from = attrs_map.get("from")
        remote_to = attrs_map.get("to")
        remote_jid = (
            remote_from
            if isinstance(remote_from, str)
            else (remote_to if isinstance(remote_to, str) else None)
        )
        observation = AckObservation(
            message_id=message_id,
            remote_jid=remote_jid,
            status="error" if error else "ok",
            error=str(error) if error is not None else None,
            attrs=dict(attrs_map),
        )
        await self._record_ack(observation)

    async def handle_event(self, event: dict[str, Any]) -> None:
        if event.get("type") != "messages.bad_ack":
            return
        bad_ack = event.get("bad_ack")
        if not isinstance(bad_ack, dict):
            return

        bad_ack_map = cast("Mapping[str, object]", bad_ack)
        message_id = bad_ack_map.get("message_id")
        if not isinstance(message_id, str) or not message_id:
            return

        error_raw = bad_ack_map.get("error")
        remote_jid_raw = bad_ack_map.get("remote_jid")
        observation = AckObservation(
            message_id=message_id,
            remote_jid=remote_jid_raw if isinstance(remote_jid_raw, str) else None,
            status="error",
            error=str(error_raw) if error_raw is not None else "unknown",
            attrs=dict(bad_ack_map),
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
