from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from waton.protocol.binary_node import BinaryNode
from waton.utils.live_check import LiveCheckConfig, LiveCheckError, run_live_check


class _FakeStorage:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class _FakeClient:
    def __init__(self, storage: _FakeStorage) -> None:
        self.storage = storage
        self.on_connection_update = self._noop_connection
        self.on_message = self._noop_message
        self.on_event = self._noop_event
        self.on_disconnected = self._noop_disconnect
        self.connect_count = 0
        self.disconnect_count = 0

    async def _noop_connection(self, event: object) -> None:
        del event

    async def _noop_message(self, node: object) -> None:
        del node

    async def _noop_event(self, event: dict[str, Any]) -> None:
        del event

    async def _noop_disconnect(self, exc: Exception) -> None:
        del exc

    async def connect(self) -> None:
        self.connect_count += 1
        await self.on_connection_update(SimpleNamespace(status="open", qr=None, reason=None))

    async def send_ping(self) -> BinaryNode:
        return BinaryNode(tag="iq", attrs={"type": "result"}, content=[])

    async def disconnect(self) -> None:
        self.disconnect_count += 1
        await self.on_connection_update(SimpleNamespace(status="close", qr=None, reason=None))
        await self.on_disconnected(Exception("closed"))


class _FakeMessages:
    def __init__(self, client: _FakeClient, *, behavior: str) -> None:
        self.client = client
        self.behavior = behavior

    async def send_text(self, to_jid: str, text: str) -> str:
        del text
        msg_id = "m-1"
        if self.behavior == "ok":
            await self.client.on_message(
                BinaryNode(
                    tag="ack",
                    attrs={"class": "message", "id": msg_id, "from": to_jid},
                )
            )
        elif self.behavior == "error":
            await self.client.on_message(
                BinaryNode(
                    tag="ack",
                    attrs={"class": "message", "id": msg_id, "from": to_jid, "error": "479"},
                )
            )
        return msg_id


@pytest.mark.asyncio
async def test_run_live_check_without_send() -> None:
    config = LiveCheckConfig(
        auth_db="dummy.db",
        test_jid=None,
        timeout_s=0.2,
        close_timeout_s=0.2,
        ack_timeout_s=0.2,
        reconnect_delay_s=0.0,
    )

    report = await run_live_check(
        config,
        storage_factory=_FakeStorage,
        client_factory=_FakeClient,
        messages_factory=lambda client: _FakeMessages(client, behavior="ok"),
    )
    assert report.open_ok is True
    assert report.ping_ok is True
    assert report.send_attempted is False
    assert report.close_ok is True
    assert report.reconnect_open_ok is True
    assert report.reconnect_ping_ok is True


@pytest.mark.asyncio
async def test_run_live_check_with_send_ack_ok() -> None:
    config = LiveCheckConfig(
        auth_db="dummy.db",
        test_jid="123@s.whatsapp.net",
        timeout_s=0.2,
        close_timeout_s=0.2,
        ack_timeout_s=0.2,
        reconnect_delay_s=0.0,
    )

    report = await run_live_check(
        config,
        storage_factory=_FakeStorage,
        client_factory=_FakeClient,
        messages_factory=lambda client: _FakeMessages(client, behavior="ok"),
    )
    assert report.send_attempted is True
    assert report.sent_message_id == "m-1"
    assert report.send_ack is not None
    assert report.send_ack.status == "ok"
    assert report.send_ack.error is None


@pytest.mark.asyncio
async def test_run_live_check_with_send_ack_error_raises() -> None:
    config = LiveCheckConfig(
        auth_db="dummy.db",
        test_jid="123@s.whatsapp.net",
        timeout_s=0.2,
        close_timeout_s=0.2,
        ack_timeout_s=0.2,
        reconnect_delay_s=0.0,
    )

    with pytest.raises(LiveCheckError, match="message ack error"):
        await run_live_check(
            config,
            storage_factory=_FakeStorage,
            client_factory=_FakeClient,
            messages_factory=lambda client: _FakeMessages(client, behavior="error"),
        )


@pytest.mark.asyncio
async def test_run_live_check_with_send_ack_timeout_raises() -> None:
    config = LiveCheckConfig(
        auth_db="dummy.db",
        test_jid="123@s.whatsapp.net",
        timeout_s=0.2,
        close_timeout_s=0.2,
        ack_timeout_s=0.05,
        reconnect_delay_s=0.0,
    )

    with pytest.raises(LiveCheckError, match="timeout waiting message ack"):
        await run_live_check(
            config,
            storage_factory=_FakeStorage,
            client_factory=_FakeClient,
            messages_factory=lambda client: _FakeMessages(client, behavior="none"),
        )
