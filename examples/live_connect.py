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
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from waton.client.client import WAClient
from waton.client.messages import MessagesAPI
from waton.core.events import ConnectionEvent
from waton.core.errors import DisconnectReason
from waton.infra.storage_sqlite import SQLiteStorage
from waton.utils.process_message import process_incoming_message
from waton.infra.storage_sqlite import SQLiteStorage

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

    opened = asyncio.Event()

    async def _on_connection_update(event: ConnectionEvent) -> None:
        print(f"[connection] status={event.status}")
        if event.qr:
            _print_qr_terminal(event.qr)
        if event.reason:
            code = getattr(event.reason, "status_code", None)
            if code is None:
                print(f"[connection] reason={event.reason}")
            else:
                print(f"[connection] reason={event.reason} (code={code})")
                if code == int(DisconnectReason.RESTART_REQUIRED):
                    print("[connection] restart required detected, reconnecting...")
        if event.status == "open":
            opened.set()

    async def _on_message(node) -> None:
        if node.tag == "message":
            try:
                msg = await process_incoming_message(node, client)
                print(f"[incoming text] from={msg.from_jid} text={msg.text!r}")
            except Exception as e:
                print(f"[decrypt error] {e}")
        else:
            print(f"[node] tag={node.tag} attrs={node.attrs}")

    async def _on_disconnected(exc: Exception) -> None:
        print(f"[disconnect] {exc}")
        opened.clear()

    client.on_connection_update = _on_connection_update
    client.on_message = _on_message
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
            print(f"Attempting send_text to {test_jid} ...")
            try:
                msg_id = await messages.send_text(test_jid, test_text)
                print(f"send_text queued with msg_id={msg_id}")
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
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
