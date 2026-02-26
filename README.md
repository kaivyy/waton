# PyWA

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**PyWA** is a lightweight, standalone Python library for WhatsApp Web Multi-Device. Build WhatsApp bots, automation tools, and messaging applications entirely in Python — no Node.js required.

## Why PyWA?

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
pip install pywa
```

> Prebuilt wheels include the Rust crypto extension — no Rust toolchain needed for installation.

For development:

```bash
pip install -e .[dev]
maturin develop
```

## Quick Start

### Basic Connection

```python
import asyncio
from pywa.client.client import WAClient
from pywa.client.messages import MessagesAPI
from pywa.infra.storage_sqlite import SQLiteStorage

async def main():
    storage = SQLiteStorage("session.db")
    client = WAClient(storage)
    messages = MessagesAPI(client)

    # Handle QR code for pairing
    async def on_connection(event):
        if event.qr:
            print(f"Scan QR: {event.qr}")
        if event.status == "open":
            print("Connected!")
            # Send a message
            await messages.send_text("1234567890@s.whatsapp.net", "Hello from PyWA!")

    client.on_connection_update = on_connection
    await client.connect()

    # Keep running
    while True:
        await asyncio.sleep(1)

asyncio.run(main())
```

### Run Example

```bash
# Basic connection with QR pairing
python -u examples/live_connect.py

# With test message
export PYWA_TEST_JID=628xxxxxxxxx@s.whatsapp.net
export PYWA_TEST_TEXT="Hello from PyWA!"
python -u examples/live_connect.py
```

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

## PyWA vs Baileys

| Aspect | PyWA (Python) | Baileys (Node.js) |
|--------|---------------|-------------------|
| **Runtime** | Python (~30-50MB) | Node.js (~50-100MB) |
| **Package Size** | ~500KB + deps | ~2MB + node_modules |
| **Crypto Engine** | Rust native (PyO3) | JS/WASM |
| **Memory Usage** | ~30-60MB | ~80-150MB |
| **Startup Time** | Faster | Slower (JIT) |
| **Encryption Speed** | Faster (native) | Slower (WASM) |
| **Maturity** | New | Mature |
| **Community** | Growing | Large |

### Choose PyWA when:

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
git clone https://github.com/kaivyy/pywa.git
cd pywa
pip install -e .[dev]
maturin develop

# Run tests
pytest tests/
```

## License

MIT License — feel free to use in personal and commercial projects.

## Disclaimer

This project is not affiliated with WhatsApp or Meta. Use responsibly and in accordance with WhatsApp's Terms of Service.
