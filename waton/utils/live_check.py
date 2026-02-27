"""End-to-end live connection reliability checker."""

from __future__ import annotations

import asyncio
import contextlib
import os
from dataclasses import dataclass
from typing import Any, Callable

from waton.client.client import WAClient
from waton.client.messages import MessagesAPI
from waton.infra.storage_sqlite import SQLiteStorage
from waton.protocol.binary_node import BinaryNode
from waton.utils.live_probe import AckObservation, LiveProbe


@dataclass
class LiveCheckConfig:
    auth_db: str = "waton_live.db"
    test_jid: str | None = None
    test_text: str = "waton live reliability probe"
    timeout_s: float = 90.0
    close_timeout_s: float = 30.0
    ack_timeout_s: float = 45.0
    reconnect_delay_s: float = 1.5
    require_reconnect: bool = True


@dataclass
class LiveCheckReport:
    open_ok: bool = False
    ping_ok: bool = False
    send_attempted: bool = False
    sent_message_id: str | None = None
    send_ack: AckObservation | None = None
    close_ok: bool = False
    reconnect_open_ok: bool = False
    reconnect_ping_ok: bool = False


class LiveCheckError(RuntimeError):
    pass


def config_from_env() -> LiveCheckConfig:
    return LiveCheckConfig(
        auth_db=os.getenv("WATON_AUTH_DB", "waton_live.db"),
        test_jid=os.getenv("WATON_TEST_JID"),
        test_text=os.getenv("WATON_TEST_TEXT", "waton live reliability probe"),
        timeout_s=float(os.getenv("WATON_LIVE_TIMEOUT", "90")),
        close_timeout_s=float(os.getenv("WATON_LIVE_CLOSE_TIMEOUT", "30")),
        ack_timeout_s=float(os.getenv("WATON_ACK_TIMEOUT", os.getenv("WATON_LIVE_TIMEOUT", "45"))),
        reconnect_delay_s=float(os.getenv("WATON_LIVE_RECONNECT_DELAY", "1.5")),
        require_reconnect=os.getenv("WATON_LIVE_RECONNECT", "1") not in {"0", "false", "False"},
    )


async def run_live_check(
    config: LiveCheckConfig,
    *,
    storage_factory: Callable[[str], Any] = SQLiteStorage,
    client_factory: Callable[[Any], Any] = WAClient,
    messages_factory: Callable[[Any], Any] = MessagesAPI,
) -> LiveCheckReport:
    storage = storage_factory(config.auth_db)
    client = client_factory(storage)
    messages = messages_factory(client)
    probe = LiveProbe()
    report = LiveCheckReport()

    async def _on_connection_update(event: object) -> None:
        await probe.handle_connection_update(event)

    async def _on_message(node: object) -> None:
        await probe.handle_message_node(node)

    async def _on_event(event: dict[str, Any]) -> None:
        await probe.handle_event(event)

    async def _on_disconnected(exc: Exception) -> None:
        await probe.handle_disconnect(exc)

    client.on_connection_update = _on_connection_update
    client.on_message = _on_message
    client.on_event = _on_event
    client.on_disconnected = _on_disconnected

    try:
        await client.connect()
        try:
            await probe.wait_open(timeout=config.timeout_s)
        except TimeoutError as exc:
            raise LiveCheckError(f"timeout waiting for open ({config.timeout_s:.1f}s)") from exc
        report.open_ok = True

        ping_node = await client.send_ping()
        if not _is_ping_result(ping_node):
            raise LiveCheckError(f"unexpected ping response: tag={ping_node.tag} attrs={ping_node.attrs}")
        report.ping_ok = True

        if config.test_jid:
            report.send_attempted = True
            msg_id = await messages.send_text(config.test_jid, config.test_text)
            report.sent_message_id = msg_id
            try:
                ack = await probe.wait_for_message_ack(msg_id, timeout=config.ack_timeout_s)
            except TimeoutError as exc:
                raise LiveCheckError(
                    f"timeout waiting message ack for {msg_id} ({config.ack_timeout_s:.1f}s)"
                ) from exc
            report.send_ack = ack
            if ack.status != "ok":
                raise LiveCheckError(
                    f"message ack error for {msg_id}: remote={ack.remote_jid} error={ack.error}"
                )

        await client.disconnect()
        try:
            await probe.wait_close(timeout=config.close_timeout_s)
        except TimeoutError as exc:
            raise LiveCheckError(f"timeout waiting for close ({config.close_timeout_s:.1f}s)") from exc
        report.close_ok = True

        if config.require_reconnect:
            if config.reconnect_delay_s > 0:
                await asyncio.sleep(config.reconnect_delay_s)

            await client.connect()
            try:
                await probe.wait_open(timeout=config.timeout_s)
            except TimeoutError as exc:
                raise LiveCheckError(f"timeout waiting for reconnect open ({config.timeout_s:.1f}s)") from exc
            report.reconnect_open_ok = True

            ping_reconnect = await client.send_ping()
            if not _is_ping_result(ping_reconnect):
                raise LiveCheckError(
                    f"unexpected reconnect ping response: tag={ping_reconnect.tag} attrs={ping_reconnect.attrs}"
                )
            report.reconnect_ping_ok = True

        return report
    finally:
        with contextlib.suppress(Exception):
            await client.disconnect()
        with contextlib.suppress(Exception):
            await storage.close()


def format_report(report: LiveCheckReport) -> str:
    lines = [
        f"open_ok={report.open_ok}",
        f"ping_ok={report.ping_ok}",
        f"send_attempted={report.send_attempted}",
        f"sent_message_id={report.sent_message_id}",
        f"send_ack_status={report.send_ack.status if report.send_ack else None}",
        f"send_ack_error={report.send_ack.error if report.send_ack else None}",
        f"close_ok={report.close_ok}",
        f"reconnect_open_ok={report.reconnect_open_ok}",
        f"reconnect_ping_ok={report.reconnect_ping_ok}",
    ]
    return "\n".join(lines)


def _is_ping_result(node: BinaryNode) -> bool:
    return node.tag == "iq" and node.attrs.get("type") == "result"
