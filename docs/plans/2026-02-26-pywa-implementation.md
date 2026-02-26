# pywa Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a complete Python+Rust WhatsApp Web Multi-Device library ported from Baileys.

**Architecture:** Hybrid approach — Baileys' proven protocol logic wrapped in Pythonic class-based architecture. 5 layers: Rust crypto → Protocol → Client → App framework → User code.

**Tech Stack:** Python 3.11+, Rust (PyO3/maturin), asyncio, websockets, httpx, protobuf, SQLite (aiosqlite), pytest, ruff, pyright

---

## Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`, `Cargo.toml`, `rust/src/lib.rs`
- Create: `ruff.toml`, `pyrightconfig.json`, `.gitignore`
- Create: `pywa/__init__.py`

**Step 1: Create `pyproject.toml` with maturin build**

```toml
[build-system]
requires = ["maturin>=1.4,<2.0"]
build-backend = "maturin"

[project]
name = "pywa"
version = "0.1.0"
description = "Python WhatsApp Web Multi-Device library"
requires-python = ">=3.11"
license = "MIT"
dependencies = [
    "websockets>=12.0",
    "httpx>=0.27",
    "protobuf>=4.25",
    "aiosqlite>=0.19",
    "qrcode>=7.4",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-xdist>=3.5",
    "hypothesis>=6.98",
    "ruff>=0.3",
    "pyright>=1.1",
    "maturin>=1.4",
]

[tool.maturin]
features = ["pyo3/extension-module"]
python-source = "."
module-name = "pywa._crypto"
manifest-path = "Cargo.toml"
```

**Step 2: Create `Cargo.toml`**

```toml
[package]
name = "pywa-crypto"
version = "0.1.0"
edition = "2021"

[lib]
name = "pywa_crypto"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.21", features = ["extension-module"] }
aes-gcm = "0.10"
x25519-dalek = { version = "2.0", features = ["static_secrets"] }
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
hkdf = "0.12"
hmac = "0.12"
sha2 = "0.10"
rand = "0.8"
curve25519-dalek = "4.1"
aes = "0.8"
ctr = "0.9"
cbc = { version = "0.1", features = ["alloc"] }
pbkdf2 = { version = "0.12", features = ["simple"] }
```

**Step 3: Create `ruff.toml`**

```toml
target-version = "py311"
line-length = 120

[lint]
select = ["E", "F", "W", "I", "N", "UP", "ANN", "B", "A", "SIM", "TCH"]
ignore = ["ANN101", "ANN102", "ANN401"]

[lint.isort]
known-first-party = ["pywa"]
```

**Step 4: Create `pyrightconfig.json`**

```json
{
  "include": ["pywa"],
  "typeCheckingMode": "strict",
  "pythonVersion": "3.11",
  "reportMissingTypeStubs": false
}
```

**Step 5: Create `.gitignore`**

```
__pycache__/
*.pyc
*.pyo
*.egg-info/
dist/
build/
target/
.venv/
*.so
*.dll
*.pyd
.ruff_cache/
.pytest_cache/
```

**Step 6: Create `pywa/__init__.py`**

```python
"""pywa - Python WhatsApp Web Multi-Device Library."""
__version__ = "0.1.0"
```

**Step 7: Create stub `rust/src/lib.rs`**

```rust
use pyo3::prelude::*;

#[pymodule]
fn pywa_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    Ok(())
}
```

**Step 8: Verify build**

```bash
cd c:\Users\Arvy Kairi\Desktop\whatsapp\pywa
pip install maturin
maturin develop
python -c "import pywa; print(pywa.__version__)"
```

**Step 9: Commit**

```bash
git init
git add -A
git commit -m "feat: project scaffolding with maturin, ruff, pyright"
```

---

## Task 2: Rust Crypto Extension

**Files:**
- Create: `rust/src/aes_gcm.rs`, `rust/src/curve.rs`, `rust/src/hkdf_utils.rs`, `rust/src/hmac_utils.rs`
- Modify: `rust/src/lib.rs`
- Test: `tests/unit/test_crypto.py`

**Step 1: Write failing crypto tests**

```python
# tests/unit/test_crypto.py
import pytest
from pywa._crypto import (
    aes_gcm_encrypt, aes_gcm_decrypt,
    curve25519_generate_keypair, curve25519_shared_key,
    curve25519_sign, curve25519_verify,
    hkdf_sha256, hmac_sha256, sha256_hash,
    aes_cbc_encrypt, aes_cbc_decrypt,
)

def test_aes_gcm_roundtrip():
    key = bytes(32)
    iv = bytes(12)
    aad = b""
    plaintext = b"hello world"
    ct = aes_gcm_encrypt(plaintext, key, iv, aad)
    pt = aes_gcm_decrypt(ct, key, iv, aad)
    assert pt == plaintext

def test_curve25519_keypair():
    kp = curve25519_generate_keypair()
    assert len(kp["private"]) == 32
    assert len(kp["public"]) == 32

def test_curve25519_shared_key():
    kp1 = curve25519_generate_keypair()
    kp2 = curve25519_generate_keypair()
    s1 = curve25519_shared_key(kp1["private"], kp2["public"])
    s2 = curve25519_shared_key(kp2["private"], kp1["public"])
    assert s1 == s2

def test_hkdf_sha256():
    result = hkdf_sha256(b"input", 32, b"salt" * 8, b"info")
    assert len(result) == 32

def test_hmac_sha256():
    result = hmac_sha256(b"key", b"data")
    assert len(result) == 32

def test_aes_cbc_roundtrip():
    key = bytes(32)
    iv = bytes(16)
    plaintext = b"hello world12345"  # 16 bytes
    ct = aes_cbc_encrypt(plaintext, key, iv)
    pt = aes_cbc_decrypt(ct, key, iv)
    assert pt == plaintext
```

**Step 2: Run test → FAIL**
```bash
pytest tests/unit/test_crypto.py -v
```

**Step 3: Implement Rust modules**

Create `rust/src/aes_gcm.rs`:
- `aes_gcm_encrypt(plaintext, key, iv, aad) -> bytes` (tag appended)
- `aes_gcm_decrypt(ciphertext, key, iv, aad) -> bytes` (tag at end)
- `aes_cbc_encrypt(plaintext, key, iv) -> bytes`
- `aes_cbc_decrypt(ciphertext, key, iv) -> bytes`
- `aes_ctr_encrypt(plaintext, key, iv) -> bytes`
- `aes_ctr_decrypt(ciphertext, key, iv) -> bytes`

Create `rust/src/curve.rs`:
- `curve25519_generate_keypair() -> {private, public}`
- `curve25519_shared_key(private, public) -> bytes`
- `curve25519_sign(private, message) -> bytes`
- `curve25519_verify(public, message, signature) -> bool`

Create `rust/src/hkdf_utils.rs`:
- `hkdf_sha256(input, length, salt, info) -> bytes`

Create `rust/src/hmac_utils.rs`:
- `hmac_sha256(key, data) -> bytes`
- `hmac_sha512(key, data) -> bytes`
- `sha256_hash(data) -> bytes`

Update `rust/src/lib.rs` to register all functions.

**Step 4: Build and test**
```bash
maturin develop
pytest tests/unit/test_crypto.py -v
```

**Step 5: Commit**
```bash
git add -A && git commit -m "feat: rust crypto extension (AES-GCM, Curve25519, HKDF, HMAC)"
```

---

## Task 3: Core Domain (Entities, JID, Errors)

**Files:**
- Create: `pywa/core/__init__.py`, `pywa/core/jid.py`, `pywa/core/entities.py`, `pywa/core/errors.py`, `pywa/core/events.py`
- Test: `tests/unit/test_jid.py`

Port `WABinary/jid-utils.ts` → `pywa/core/jid.py`:
- `jid_decode(jid) -> FullJid | None`
- `jid_encode(user, server, device?) -> str`
- `jid_normalized_user(jid) -> str`
- `is_jid_group(jid)`, `is_jid_user(jid)`, `is_lid_user(jid)`, etc.
- `S_WHATSAPP_NET = "s.whatsapp.net"`

Port entities: `BinaryNode` dataclass, `Message`, `Chat`, `Contact`, `GroupMetadata`.
Port errors: `DisconnectReason` enum, custom exceptions.
Port events: Event type definitions matching Baileys event model.

TDD: Write tests for JID parsing/encoding first, then implement.

---

## Task 4: Binary Node Codec

**Files:**
- Create: `pywa/protocol/__init__.py`, `pywa/protocol/binary_node.py`, `pywa/protocol/constants.py`, `pywa/protocol/binary_codec.py`
- Test: `tests/unit/test_binary_codec.py`, `tests/golden/test_golden_codec.py`

**Step 1: Port `constants.ts` → `constants.py`**

Exact copy of TAGS, SINGLE_BYTE_TOKENS (243 entries), DOUBLE_BYTE_TOKENS (4 arrays × 257 entries), TOKEN_MAP (reverse lookup).

**Step 2: Write codec tests**

```python
# tests/unit/test_binary_codec.py
from pywa.protocol.binary_node import BinaryNode
from pywa.protocol.binary_codec import encode_binary_node, decode_binary_node

def test_simple_node_roundtrip():
    node = BinaryNode(tag="iq", attrs={"type": "get", "to": "s.whatsapp.net"})
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.tag == node.tag
    assert decoded.attrs == node.attrs

def test_node_with_content():
    node = BinaryNode(tag="message", attrs={"id": "123"}, content=b"hello")
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.content == b"hello"

def test_nested_nodes():
    child = BinaryNode(tag="ping", attrs={})
    node = BinaryNode(tag="iq", attrs={"type": "get"}, content=[child])
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert len(decoded.content) == 1
    assert decoded.content[0].tag == "ping"

def test_jid_encoding():
    node = BinaryNode(tag="iq", attrs={"to": "123@s.whatsapp.net"})
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.attrs["to"] == "123@s.whatsapp.net"
```

**Step 3: Implement `binary_codec.py`**

Port `encode.ts` and `decode.ts` exactly:
- `encode_binary_node(node) -> bytes`
- `decode_binary_node(data: bytes) -> BinaryNode`
- Internal: token lookup, nibble/hex packing, JID encoding, list size encoding

**Step 4: Run tests**
```bash
pytest tests/unit/test_binary_codec.py -v
ruff check pywa/
pyright pywa/
```

**Step 5: Commit**
```bash
git add -A && git commit -m "feat: binary node codec (encode/decode with token dictionaries)"
```

---

## Task 5: Protobuf Schema Generation

**Files:**
- Copy: `WAProto/WAProto.proto` → `pywa/protocol/protobuf/WAProto.proto`
- Generate: `pywa/protocol/protobuf/WAProto_pb2.py`
- Create: `pywa/protocol/protobuf/__init__.py`

```bash
# Install protoc
pip install grpcio-tools
# Generate
python -m grpc_tools.protoc -I=pywa/protocol/protobuf --python_out=pywa/protocol/protobuf pywa/protocol/protobuf/WAProto.proto
```

---

## Task 6: Noise Handler

**Files:**
- Create: `pywa/protocol/noise_handler.py`
- Create: `pywa/utils/crypto.py` (Python wrappers for Rust crypto)
- Test: `tests/unit/test_noise.py`

Port `noise-handler.ts` exactly:
- `NoiseHandler` class with state machine
- `process_handshake(server_hello, noise_key) -> key_enc`
- `encode_frame(data) -> bytes` (3-byte length prefix)
- `decode_frame(data, on_frame)` (accumulate + decrypt + decode)
- `TransportState` class (read/write counters, encrypt/decrypt)
- NOISE_MODE = `"Noise_XX_25519_AESGCM_SHA256\0\0\0\0"`

---

## Task 7: WebSocket Transport

**Files:**
- Create: `pywa/infra/websocket.py`
- Test: `tests/unit/test_websocket.py`

Implement WebSocket client using `websockets` library:
- `WebSocketTransport` class
- `connect(url)`, `send(data)`, `close()`
- Event handlers: `on_message`, `on_close`, `on_error`
- Ping/pong support

---

## Task 8: Auth & Credentials

**Files:**
- Create: `pywa/utils/auth.py`, `pywa/defaults/config.py`
- Create: `pywa/infra/storage_sqlite.py`, `pywa/infra/storage_json.py`
- Test: `tests/unit/test_auth.py`, `tests/unit/test_storage.py`

Port `auth-utils.ts`:
- `init_auth_creds() -> AuthCreds` (generate identity keys, registration id, etc.)
- `makeCacheableSignalKeyStore` → `CacheableSignalKeyStore`
- `addTransactionCapability` → transaction decorator

Port `Defaults/index.ts` → `defaults/config.py`:
- All constants: `NOISE_WA_HEADER`, `WA_CERT_DETAILS`, `DEFAULT_CONNECTION_CONFIG`, etc.

Storage protocol + SQLite implementation:
- Tables: `creds`, `sessions`, `prekeys`, `sender_keys`, `app_state`

---

## Task 9: Signal Protocol Repository

**Files:**
- Create: `pywa/protocol/signal_repo.py`, `pywa/protocol/group_cipher.py`
- Test: `tests/unit/test_signal.py`

Port `Signal/libsignal.ts`:
- `SignalRepository` class
- `encrypt_message(jid, data)`, `decrypt_message(jid, type, ciphertext)`
- `encrypt_group_message(group, me_id, data)`, `decrypt_group_message(group, author, msg)`
- Session validation, prekey management

Port `Signal/Group/`:
- `SenderKeyName`, `SenderKeyRecord`, `SenderKeyState`
- `GroupSessionBuilder`, `GroupCipher`, `SenderKeyDistributionMessage`

---

## Task 10: WAClient (Core Socket)

**Files:**
- Create: `pywa/client/__init__.py`, `pywa/client/client.py`
- Test: `tests/unit/test_client.py`

Port `Socket/socket.ts` into `WAClient` class:
- `connect()` → WebSocket + Noise handshake + login/register
- `query(node, timeout)` → send node + wait for response
- `send_node(frame)` → encode + encrypt + send
- `_on_message_received(data)` → decrypt + decode + dispatch
- `logout()`, `_end(error)`
- Keep-alive ping/pong loop
- Pre-key upload/rotation logic
- Pairing code / QR code support

---

## Task 11: Message Send/Receive

**Files:**
- Create: `pywa/client/messages.py`
- Create: `pywa/utils/message_utils.py`, `pywa/utils/process_message.py`
- Test: `tests/unit/test_messages.py`

Port `Socket/messages-send.ts` + `Socket/messages-recv.ts`:
- `send_message(jid, content, options)` → generate + encrypt + relay
- `relay_message(jid, message, options)` → device fanout + participant nodes
- `send_receipt(jid, participant, msg_ids, type)`
- `_handle_message(node)` → decrypt + process + emit events
- `_handle_receipt(node)` → update delivery status
- `_handle_notification(node)` → process notifications
- Retry manager for failed messages

---

## Task 12: Chat, Group, Presence, Media

**Files:**
- Create: `pywa/client/chats.py`, `pywa/client/groups.py`, `pywa/client/presence.py`, `pywa/client/media.py`
- Create: `pywa/utils/media_utils.py`, `pywa/utils/chat_utils.py`
- Test: `tests/unit/test_chats.py`, `tests/unit/test_groups.py`

Port chats: privacy settings, profile picture, blocklist, app state sync.
Port groups: create, update, participants, metadata.
Port presence: typing, online/offline.
Port media: encrypted upload/download, thumbnail generation, media key derivation.

---

## Task 13: App Framework (High-Level)

**Files:**
- Create: `pywa/app/__init__.py`, `pywa/app/app.py`, `pywa/app/router.py`, `pywa/app/filters.py`, `pywa/app/middleware.py`, `pywa/app/context.py`
- Test: `tests/unit/test_app.py`, `tests/unit/test_filters.py`

Build decorator-based bot framework:
- `App` class with `@app.message()`, `@app.command()`, `@app.on_ready`
- `Filter` combinators: `text`, `private`, `group`, `regex`, `command`
- `Context` class: `reply()`, `react()`, `forward()`, `delete()`
- `Middleware` pipeline
- `Router` for multi-module bots
- `app.run()` → connect + event loop

---

## Task 14: Communities & Newsletter

**Files:**
- Create: `pywa/client/communities.py`, `pywa/client/newsletter.py`

Port `Socket/communities.ts` and `Socket/newsletter.ts`.

---

## Task 15: Event Buffer & Utilities

**Files:**
- Create: `pywa/utils/event_buffer.py`, `pywa/utils/generics.py`, `pywa/utils/lt_hash.py`
- Create: `pywa/infra/logger.py`

Port `Utils/event-buffer.ts`, `Utils/generics.ts`, `Utils/lt-hash.ts`.
Structured JSON logging with Python `logging` module.

---

## Task 16: Lint, Type Check & Final Verification

**Step 1: Run ruff**
```bash
ruff check pywa/ --fix
ruff format pywa/
```

**Step 2: Run pyright**
```bash
pyright pywa/
```

**Step 3: Run all tests**
```bash
pytest tests/ -v --tb=short
```

**Step 4: Run Rust tests**
```bash
cargo test
```

**Step 5: Build final wheel**
```bash
maturin build --release
```

**Step 6: Verify import**
```python
from pywa import App, filters
from pywa.client import WAClient
print("pywa ready!")
```

**Step 7: Final commit**
```bash
git add -A && git commit -m "feat: complete pywa library v0.1.0"
```

---

## Verification Summary

| Check | Command | Expected |
|---|---|---|
| Lint | `ruff check pywa/` | 0 errors |
| Type check | `pyright pywa/` | 0 errors |
| Unit tests | `pytest tests/unit/ -v` | All PASS |
| Golden tests | `pytest tests/golden/ -v` | All PASS |
| Rust tests | `cargo test` | All PASS |
| Build wheel | `maturin build --release` | Success |
| Import | `python -c "import pywa"` | No error |
