"""Interactive Terminal Chat application for Waton.

Usage:
    python examples/cli_chat.py
"""

import asyncio
import os
import sys
from pathlib import Path
import logging

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

from waton.app.app import App
from waton.app.context import Context

db_path = os.getenv("WATON_AUTH_DB", "waton_live.db")
app = App(storage_path=db_path)
debug_nodes_enabled = os.getenv("WATON_CLI_DEBUG_NODES", "").strip().lower() in {"1", "true", "yes", "on"}
debug_include_ib = os.getenv("WATON_CLI_DEBUG_IB", "").strip().lower() in {"1", "true", "yes", "on"}

if not debug_nodes_enabled:
    # Keep CLI clean by default so input prompt remains usable.
    logging.getLogger("waton.utils.process_message").setLevel(logging.ERROR)

@app.on_ready
async def on_ready(a: App) -> None:
    print("\n" + "="*50)
    print("WhatsApp Bot Connected & Ready!")
    print("="*50)
    print("Ketik pesan dengan format: nomor pesan")
    print("Contoh: 628123456789 halo apa kabar?")
    print("Ketik 'quit' atau 'exit' untuk keluar.\n")
    
    # Start the input watcher loop in the background
    asyncio.create_task(cli_input_loop(a))


@app.message()
async def on_incoming_message(ctx: Context) -> None:
    msg = ctx.message
    if msg.text is None and msg.raw_node.tag == "message" and msg.message_type == "text":
        print(f"\n[PESAN MASUK - UNDECRYPTED] dari {msg.from_jid}: id={msg.id}")
        print("> ", end="", flush=True)
        return
    if msg.text and msg.media_url:
        print(f"\n[PESAN MASUK - MEDIA] dari {msg.from_jid}: {msg.text} (URL: {msg.media_url})")
        print("> ", end="", flush=True)
    elif msg.text:
        print(f"\n[PESAN MASUK] dari {msg.from_jid}: {msg.text}")
        print("> ", end="", flush=True)
    elif msg.media_url:
        print(f"\n[PESAN MASUK - MEDIA] dari {msg.from_jid} (URL: {msg.media_url})")
        print("> ", end="", flush=True)
    else:
        print(f"\n[PESAN MASUK (NON-TEKS)] dari {msg.from_jid}: tag={msg.raw_node.tag}")
        print("> ", end="", flush=True)

# Optional node-level debug (disabled by default to avoid flooding prompt).
if debug_nodes_enabled:
    original_dispatch = app._dispatch_message

    async def debug_dispatch(node):
        if node.tag in ("iq", "success"):
            await original_dispatch(node)
            return
        if node.tag == "ib" and not debug_include_ib:
            await original_dispatch(node)
            return
        print(f"\n[DEBUG] Incoming node: <{node.tag}> attrs={node.attrs}")
        print("> ", end="", flush=True)
        await original_dispatch(node)

    app.client.on_message = debug_dispatch


async def cli_input_loop(a: App) -> None:
    loop = asyncio.get_running_loop()
    while True:
        # Run standard python input() without blocking the async event loop
        try:
            line = await loop.run_in_executor(None, input, "> ")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            os._exit(0)
        line = line.strip()
        
        if not line:
            continue
            
        if line.lower() in ("quit", "exit"):
            print("Exiting...")
            os._exit(0)
            
        parts = line.split(" ", 1)
        if len(parts) < 2:
            print("[System] Format salah! Gunakan: nomor pesan")
            continue
            
        target_number = parts[0]
        text_message = parts[1]
        
        # Simple formatting for target jid
        if not target_number.endswith("@s.whatsapp.net") and not target_number.endswith("@g.us"):
            target_number = f"{target_number}@s.whatsapp.net"
            
        try:
            print(f"[Debug] is_authenticated={a.client.is_authenticated} creds.me={a.client.creds.me if a.client.creds else None}")
            if text_message.startswith("/image "):
                image_path = text_message[7:].strip()
                caption = "Sent from Waton CLI"
                if not os.path.exists(image_path):
                    print(f"[System] File tidak ditemukan: {image_path}")
                    continue
                with open(image_path, "rb") as f:
                    image_bytes = f.read()
                print(f"[System] Mengirim gambar ke {target_number}...")
                msg_id = await a.messages.send_image(target_number, image_bytes, caption)
                print(f"[System] Berhasil kirim gambar! Message ID: {msg_id}")
            else:
                print(f"[System] Mengirim pesan ke {target_number}...")
                msg_id = await a.messages.send_text(target_number, text_message)
                print(f"[System] Berhasil! Message ID: {msg_id}")
        except Exception as e:
            print(f"[System] Gagal mengirim pesan: {e}")

if __name__ == "__main__":
    try:
        app.run()
    except KeyboardInterrupt:
        print("\nExited.")
