<p align="center">
  <img src="image/watonimg.png" width="100%" alt="Waton Banner">
</p>

<div align="center">

# Waton

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
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

### Windows troubleshooting: `os error 32` during editable install

If you get:

- `failed to copy ... waton\\_crypto.pyd`
- `The process cannot access the file because it is being used by another process. (os error 32)`

then `_crypto.pyd` is locked by another running Python process (usually `examples/cli_chat.py` or `examples/live_connect.py`).

Fix:

```powershell
# from project root
Get-CimInstance Win32_Process -Filter "name='python.exe'" `
  | Where-Object { $_.CommandLine -match 'examples/cli_chat.py|examples/live_connect.py' } `
  | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

python -m pip install -e .[dashboard]
```

If you only want the browser dashboard and do not need reinstall, you can skip editable reinstall and just run:

```powershell
python -m tools.dashboard.server --host 127.0.0.1 --port 8080
```

### Package Footprint (`pip install waton`)

Published artifacts are intentionally runtime-only:
- included: `waton/`, Rust extension module, metadata files
- excluded from source distribution: `docs/`, `examples/`, `tests/`, `tools/`

Quick verification commands:

```bash
python -m pip wheel . --no-deps -w .tmp-wheel
python -m maturin sdist --manifest-path Cargo.toml --out .tmp-sdist
```

## How To Use

Waton now provides a **simple callback API** for fastest onboarding, plus the existing high-level `App` and low-level `WAClient` interfaces.

### 0. Simple Callback API (Drop-in Easiest)

If you want the shortest path from import to running bot:

```python
from waton import simple

client = simple(storage_path="my_session.db")

@client.on_message
async def on_message(msg):
    if msg.text:
        await msg.reply(f"Echo: {msg.text}")

@client.on_ready
async def on_ready(bot):
    print("Waton simple client is connected")

if __name__ == "__main__":
    client.run()
```

`msg` provides:
- `msg.id`
- `msg.text`
- `msg.from_jid`
- `msg.sender`
- `await msg.reply(text)`
- `await msg.react(emoji)`

Use this mode when you want minimal boilerplate while keeping the same core runtime.

### 1. Interactive CLI Chat (Easiest Way to Test)

We provide a built-in interactive terminal chat. If you just want to test sending and receiving messages via your terminal, run:

```bash
python examples/cli_chat.py
```

- When you run this for the first time, it will print a QR code in the terminal. Scan it with your WhatsApp app (Linked Devices).
- Once connected, any incoming messages to your number will be printed live in the terminal.
- To send a message, simply type `NOMOR_TUJUAN pesan yang ingin dikirim` (e.g., `628123456789 Halo dari terminal!`) and press Enter.

### 1.5 One-Command Live Reliability Check

To validate connect/ping/send-ack/reconnect in one command:

```bash
python scripts/live_check.py --auth-db waton_live.db --test-jid 628123456789@s.whatsapp.net --test-text "hello from waton"
```

If `--test-jid` is omitted, the check still validates connect/ping/reconnect without send-ack.

### 1.6 One-Command Release Preflight

Run all release gates (tests, parity scan, and optional lint/typecheck/live):

```bash
python scripts/preflight_check.py
```

Fast local run (skip lint/typecheck):

```bash
python scripts/preflight_check.py --skip-lint --skip-typecheck
```

### 1.7 Browser Dashboard for Quick Testing

If you want a browser UI instead of terminal-only testing:

```bash
pip install -e .[dashboard]
python -m tools.dashboard.server --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

- Security note: keep dashboard bound to local host (`127.0.0.1`) unless protected by a trusted reverse proxy/auth layer.
- The dashboard is isolated in `tools/dashboard/` and does not modify core runtime modules.
- It uses real WhatsApp connection flow (QR pairing + real send API).
- Status will show:
  - `connected` when WA session is open and authenticated
  - `connecting` while waiting QR/pairing
  - `disconnected` when socket is not connected
- In disconnected state, you must connect and scan QR first before sending.
- UI follows WhatsApp Web style:
  - left panel: chat list (auto-populates from real incoming/outgoing chats)
  - right panel: active chat thread
  - if new message arrives from another number, it appears in left list and can be opened in right thread
  - footer composer is WhatsApp-like (attach/emoji placeholders + autosize text input + send button)
- Debug endpoint for root-cause tracing:
  - open `http://127.0.0.1:8080/api/debug/summary`
  - check `chat_count`, `chats`, and `events_tail` to verify whether incoming nodes are reaching dashboard runtime.

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

- Python 3.11+
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

## Documentation (Read the Docs)

Sphinx docs source is in `docs/source/` with RTD config in `.readthedocs.yaml`.

Local docs build:

```bash
pip install -e .[docs]
python -m sphinx -b html docs/source docs/build/html
```

## License

MIT License — feel free to use in personal and commercial projects.

## Disclaimer

This project is not affiliated with WhatsApp or Meta. Use responsibly and in accordance with WhatsApp's Terms of Service.
