<p align="center">
  <img src="image/watonimg.png" width="100%" alt="Waton Banner">
</p>

<div align="center">

# Waton

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Waton** is a lightweight, standalone Python library for WhatsApp Web Multi-Device. Build WhatsApp bots, automation tools, and messaging applications entirely in Python — no Node.js required.

</div>

## Why Waton?

- **Pure Python** — Native async/await API, integrates seamlessly with your Python stack
- **Blazing Fast Crypto** — Signal Protocol encryption powered by Rust (via PyO3)
- **Lightweight** — ~30-60MB memory footprint, minimal dependencies
- **Multi-Device Ready** — Full support for WhatsApp's multi-device architecture
- **No Node.js** — Not a Baileys wrapper, zero JavaScript runtime dependency

## Features

- QR Code & Phone Number Pairing
- Send & Receive Text Messages
- Multi-Device Message Routing
- End-to-End Encryption (Signal Protocol)
- Persistent Session Storage (SQLite)
- Async/Await Native API

## Installation

```bash
pip install waton
```

> Prebuilt wheels include the Rust crypto extension — no Rust toolchain needed for installation.

For development:

```bash
pip install -e .[dev]
maturin develop
```

## How To Use

Waton provides both a high-level `App` interface (recommended) and a low-level `WAClient` interface. 

### 1. Interactive CLI Chat (Easiest Way to Test)

We provide a built-in interactive terminal chat. If you just want to test sending and receiving messages via your terminal, run:

```bash
python examples/cli_chat.py
```

- When you run this for the first time, it will print a QR code in the terminal. Scan it with your WhatsApp app (Linked Devices).
- Once connected, any incoming messages to your number will be printed live in the terminal.
- To send a message, simply type `NOMOR_TUJUAN pesan yang ingin dikirim` (e.g., `628123456789 Halo dari terminal!`) and press Enter.

### 2. High-Level API (`App`)

For building bots or automated tools, use the `App` class. It manages the connection, storage, and message parsing automatically, providing a simple decorator-based router.

```python
import asyncio
from waton.app.app import App
from waton.app.context import Context

# 1. Initialize App (creates SQLite session DB)
app = App(storage_path="my_session.db")

# 2. Listen for incoming messages
@app.message()
async def on_message(ctx: Context):
    msg = ctx.message
    print(f"Message received from {msg.from_jid}: {msg.text}")
    
    # Auto-reply if there is text
    if msg.text:
        reply_text = f"Hello! You said: {msg.text}"
        await ctx.app.messages.send_text(to_jid=msg.from_jid, text=reply_text)

# 3. Connection ready callback
@app.on_ready
async def on_ready(app_instance: App):
    print("Bot is connected and ready to receive messages!")

# 4. Run the loop
if __name__ == "__main__":
    app.run()
```

### 3. Low-Level API (`WAClient`)

If you want direct control over the WebSocket or need to build custom wrappers, you can use the WAClient directly. See `examples/live_connect.py` for a full example.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Your App                       │
├─────────────────────────────────────────────────┤
│  MessagesAPI  │  ChatsAPI  │  GroupsAPI  │ ...  │
├─────────────────────────────────────────────────┤
│                   WAClient                       │
│         (WebSocket + Noise Protocol)             │
├─────────────────────────────────────────────────┤
│              Signal Protocol (E2EE)              │
│           ┌─────────────────────┐                │
│           │   Rust Crypto Core  │                │
│           │  (Curve25519, AES)  │                │
│           └─────────────────────┘                │
├─────────────────────────────────────────────────┤
│           SQLiteStorage (Sessions)               │
└─────────────────────────────────────────────────┘
```

## Waton vs Baileys

| Aspect | Waton (Python) | Baileys (Node.js) |
|--------|---------------|-------------------|
| **Runtime** | Python (~30-50MB) | Node.js (~50-100MB) |
| **Package Size** | ~500KB + deps | ~2MB + node_modules |
| **Crypto Engine** | Rust native (PyO3) | JS/WASM |
| **Memory Usage** | ~30-60MB | ~80-150MB |
| **Startup Time** | Faster | Slower (JIT) |
| **Encryption Speed** | Faster (native) | Slower (WASM) |
| **Maturity** | New | Mature |
| **Community** | Growing | Large |

### Choose Waton when:

- Building Python-native applications
- Running on resource-constrained environments (VPS, Raspberry Pi, Docker)
- Need minimal memory footprint
- Want native async/await integration with FastAPI, Django, etc.

### Choose Baileys when:

- Already invested in Node.js ecosystem
- Need battle-tested stability for production
- Require extensive community support and plugins

## Requirements

- Python 3.10+
- WhatsApp account (phone number)
- Internet connection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

```bash
# Setup development environment
git clone https://github.com/kaivyy/waton.git
cd waton
pip install -e .[dev]
maturin develop

# Run tests
pytest tests/
```

## License

MIT License — feel free to use in personal and commercial projects.

## Disclaimer

This project is not affiliated with WhatsApp or Meta. Use responsibly and in accordance with WhatsApp's Terms of Service.
