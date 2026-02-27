# ruff: noqa: E402
"""Live WhatsApp connection runner for QR/connect/manual test.

Usage:
    python examples/live_connect.py

Optional env:
    WATON_AUTH_DB=waton_live.db
    WATON_TEST_JID=62812xxxx@s.whatsapp.net
    WATON_TEST_TEXT=hello from waton
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from waton.client.client import WAClient
from waton.client.messages import MessagesAPI
from waton.core.errors import DisconnectReason
from waton.infra.storage_sqlite import SQLiteStorage
from waton.utils.live_probe import LiveProbe
from waton.utils.process_message import process_incoming_message

try:
    import qrcode
except ImportError:  # pragma: no cover - optional at runtime
    qrcode = None


def _print_qr_terminal(qr_text: str) -> None:
    print("\n=== QR STRING ===")
    print(qr_text)
    if qrcode is None:
        print("qrcode package not installed; showing raw QR string only.")
        return
    print("\n=== QR TERMINAL ===")
    qr = qrcode.QRCode(border=1)
    qr.add_data(qr_text)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


async def main() -> None:
    db_path = os.getenv("WATON_AUTH_DB", "waton_live.db")
    storage = SQLiteStorage(db_path)
    client = WAClient(storage)
    messages = MessagesAPI(client)
    probe = LiveProbe()

    opened = asyncio.Event()

    async def _on_connection_update(event: object) -> None:
        await probe.handle_connection_update(event)
        status = getattr(event, "status", None)
        qr = getattr(event, "qr", None)
        reason = getattr(event, "reason", None)
        print(f"[connection] status={status}")
        if qr:
            _print_qr_terminal(qr)
        if reason:
            code = getattr(reason, "status_code", None)
            if code is None:
                print(f"[connection] reason={reason}")
            else:
                print(f"[connection] reason={reason} (code={code})")
                if code == int(DisconnectReason.RESTART_REQUIRED):
                    print("[connection] restart required detected, reconnecting...")
        if status == "open":
            opened.set()

    async def _on_message(node: object) -> None:
        await probe.handle_message_node(node)
        if not hasattr(node, "tag") or not hasattr(node, "attrs"):
            return
        if node.tag == "message":
            try:
                msg = await process_incoming_message(node, client)
                print(f"[incoming text] from={msg.from_jid} text={msg.text!r}")
            except Exception as e:
                print(f"[decrypt error] {e}")
        else:
            print(f"[node] tag={node.tag} attrs={node.attrs}")

    async def _on_event(event: dict) -> None:
        await probe.handle_event(event)
        event_type = event.get("type")
        if event_type == "messages.receipt":
            receipt = event.get("receipt", {})
            print(
                f"[receipt] from={receipt.get('from')} "
                f"type={receipt.get('receipt_type')} ids={receipt.get('message_ids', [])}"
            )
        elif event_type == "messages.retry_request":
            receipt = event.get("receipt", {})
            print(
                f"[retry] from={receipt.get('from')} ids={receipt.get('message_ids', [])} "
                f"count={receipt.get('retry', {}).get('count')} allowed={event.get('retry_allowed')}"
            )
        elif event_type == "messages.retry_request_sent":
            req = event.get("retry_request", {})
            print(
                f"[retry-sent] to={req.get('to')} id={req.get('id')} "
                f"count={req.get('count')} sent={req.get('sent')}"
            )
        elif event_type == "messages.bad_ack":
            bad_ack = event.get("bad_ack", {})
            print(
                f"[bad-ack] jid={bad_ack.get('remote_jid')} id={bad_ack.get('message_id')} "
                f"error={bad_ack.get('error')}"
            )
        elif event_type == "messages.notification":
            notif = event.get("notification", {})
            print(
                f"[notification] kind={notif.get('kind')} "
                f"from={notif.get('from')} children={notif.get('children', [])}"
            )
            if notif.get("newsletter_event"):
                print(f"[newsletter-notification] {notif.get('newsletter_event')}")
        elif event_type == "messages.protocol_notification":
            notif = event.get("protocol_notification", {})
            print(f"[protocol] from={notif.get('from')} children={notif.get('children', [])}")
        elif event_type in {
            "messages.revoke",
            "messages.edit",
            "messages.history_sync",
            "messages.app_state_sync_key_share",
            "messages.group_member_label_change",
            "messages.ephemeral_setting",
            "messages.reaction_encrypted",
            "messages.poll_update_encrypted",
            "messages.event_response_encrypted",
            "messages.protocol",
        }:
            protocol = event.get("protocol", {})
            if protocol:
                print(
                    f"[protocol-message] type={protocol.get('type_name')} "
                    f"target={protocol.get('target_message_id')} id={event.get('message', {}).get('id')}"
                )
            else:
                print(f"[encrypted-addon] type={event_type} id={event.get('message', {}).get('id')}")

    async def _on_disconnected(exc: Exception) -> None:
        await probe.handle_disconnect(exc)
        print(f"[disconnect] {exc}")
        opened.clear()

    client.on_connection_update = _on_connection_update
    client.on_message = _on_message
    client.on_event = _on_event
    client.on_disconnected = _on_disconnected

    try:
        await client.connect()
        print("Handshake complete. Waiting for scan/auth...")
        await opened.wait()
        print("Connection open. Running ping test...")

        try:
            pong = await client.send_ping()
            print(f"Ping OK: tag={pong.tag} attrs={pong.attrs}")
        except Exception as exc:
            print(f"Ping test failed: {exc}")

        test_jid = os.getenv("WATON_TEST_JID")
        if test_jid:
            test_text = os.getenv("WATON_TEST_TEXT", "hello from waton")
            ack_timeout = float(os.getenv("WATON_ACK_TIMEOUT", "45"))
            print(f"Attempting send_text to {test_jid} ...")
            try:
                msg_id = await messages.send_text(test_jid, test_text)
                print(f"send_text queued with msg_id={msg_id}")
                try:
                    ack = await probe.wait_for_message_ack(msg_id, timeout=ack_timeout)
                    if ack.status == "ok":
                        print(f"[send-ack] id={msg_id} status=ok remote={ack.remote_jid}")
                    else:
                        print(
                            f"[send-ack] id={msg_id} status=error "
                            f"remote={ack.remote_jid} error={ack.error}"
                        )
                except TimeoutError:
                    print(f"[send-ack] timeout waiting ack for id={msg_id} after {ack_timeout:.1f}s")
            except Exception as exc:
                print(f"send_text failed: {exc}")
        else:
            print("Set WATON_TEST_JID to run send_text test.")

        print("Listening for events. Ctrl+C to stop.")
        while True:
            await asyncio.sleep(1)
    finally:
        await client.disconnect()
        await storage.close()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
