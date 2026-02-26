# Receive Messages Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement end-to-end decryption for incoming WhatsApp messages (`pkmsg` and `msg`), decoding the PKCS#7 padded protobuf payloads, and emitting incoming message events.

**Architecture:** Incoming XMPP stanzas containing `<enc>` nodes will be handed to the `MessagesAPI` (or a dedicated receiver module). The payload will be passed to `SignalRepository.decrypt_message()`. Since PyWA's Rust extension currently only supports encryption, we first need to expose `wa-rs-libsignal`'s decryption methods to Python. After decryption, the PKCS#7 padding is removed, the protobuf is deserialized, and the final message data is returned/emitted.

**Tech Stack:** Rust (`wa-rs-libsignal`, PyO3), Python (Protobuf), Pytest.

---

### Task 1: Add Decryption to Rust Extension `signal.rs`

**Files:**
- Modify: `rust/src/signal.rs`
- Modify: `rust/src/lib.rs`
- Modify: `pywa/utils/crypto.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_rust_crypto.py
import pytest
from pywa.utils.crypto import signal_session_decrypt_prekey, signal_session_decrypt_whisper

def test_rust_decrypt_missing():
    # Just verify they exist and are callable (will fail initially)
    assert callable(signal_session_decrypt_prekey)
    assert callable(signal_session_decrypt_whisper)
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_rust_crypto.py -v`
Expected: FAIL due to missing functions.

**Step 3: Write minimal implementation**

In `rust/src/signal.rs`, add decryption functions using `message_decrypt_prekey` and `message_decrypt`:
```rust
use wa_rs_libsignal::protocol::{
    message_decrypt_prekey, message_decrypt, PreKeySignalMessage, SignalMessage,
};

pub fn decrypt_with_session_prekey(
    session: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    ciphertext: &[u8],
) -> Result<EncryptedPayload, String> {
    let address = signal_address(remote_name, remote_device);
    let identity_pair = to_identity_keypair(identity_private)?;
    let mut session_store = OneSessionStore::new(address.clone(), Some(session))?;
    let mut identity_store = OneIdentityStore::new(identity_pair, registration_id);

    let message = PreKeySignalMessage::deserialize(ciphertext)
        .map_err(|e| format!("Invalid prekey message: {}", e))?;

    let plaintext = block_on(message_decrypt_prekey(
        &message,
        &address,
        &mut session_store,
        &mut identity_store,
    )).map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(EncryptedPayload {
        msg_type: "plaintext".to_string(), // Or keep original
        ciphertext: plaintext,
        session: session_store.serialize_session()?,
    })
}

pub fn decrypt_with_session_whisper(
    session: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    ciphertext: &[u8],
) -> Result<EncryptedPayload, String> {
    let address = signal_address(remote_name, remote_device);
    let identity_pair = to_identity_keypair(identity_private)?;
    let mut session_store = OneSessionStore::new(address.clone(), Some(session))?;
    let mut identity_store = OneIdentityStore::new(identity_pair, registration_id);

    let message = SignalMessage::deserialize(ciphertext)
        .map_err(|e| format!("Invalid whisper message: {}", e))?;

    let plaintext = block_on(message_decrypt(
        &message,
        &address,
        &mut session_store,
        &mut identity_store,
    )).map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(EncryptedPayload {
        msg_type: "plaintext".to_string(),
        ciphertext: plaintext,
        session: session_store.serialize_session()?,
    })
}
```

In `rust/src/lib.rs`, wrap and export them via PyO3.
In `pywa/utils/crypto.py`, import and expose them.

Wait, to compile the Rust extension, you must run `maturin develop`.

**Step 4: Run test to verify it passes**

Run: `maturin develop` then `pytest tests/unit/test_rust_crypto.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add rust/ pywa/utils/crypto.py tests/
git commit -m "feat: add signal_session_decrypt functions to rust extension"
```

---

### Task 2: Implement decrypt_message in SignalRepository

**Files:**
- Modify: `pywa/protocol/signal_repo.py`
- Modify: `tests/unit/test_signal.py`

**Step 1: Write the failing test**

```python
# Add to tests/unit/test_signal.py
@pytest.mark.asyncio
async def test_signal_decrypt_message() -> None:
    # Build a fake session, encrypt a message, then decrypt it
    # Assert plaintext matches
    pass
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_signal.py::test_signal_decrypt_message -v`
Expected: FAIL (NotImplementedError)

**Step 3: Write minimal implementation**

In `signal_repo.py`:
```python
    async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
        signal_name, signal_device = self.jid_to_signal_address(jid)
        session = await self.get_session(jid)
        if not session:
            raise ValueError(f"No session found for {jid}")
            
        if type_str == "pkmsg":
            result = signal_session_decrypt_prekey(
                session,
                self.creds.signed_identity_key["private"],
                int(self.creds.registration_id),
                signal_name,
                int(signal_device),
                ciphertext,
            )
        elif type_str == "msg":
            result = signal_session_decrypt_whisper(
                session,
                self.creds.signed_identity_key["private"],
                int(self.creds.registration_id),
                signal_name,
                int(signal_device),
                ciphertext,
            )
        else:
            raise ValueError(f"Unknown message type: {type_str}")
            
        await self.save_session(jid, bytes(result["session"]))
        return bytes(result["ciphertext"])
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_signal.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add pywa/protocol/signal_repo.py tests/unit/test_signal.py
git commit -m "feat: implement SignalRepository decrypt_message"
```

---

### Task 3: Unpad and Parse Protobuf Payload

**Files:**
- Modify: `pywa/client/messages.py`

**Step 1: Write the failing test**

```python
# In test_messages.py
def test_unpad_random_max16():
    # Test stripping PKCS7 padding
    from pywa.client.messages import _unpad_random_max16
    padded = b"helloworld" + bytes([5] * 5)
    assert _unpad_random_max16(padded) == b"helloworld"
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_messages.py::test_unpad_random_max16 -v`

**Step 3: Write minimal implementation**

```python
def _unpad_random_max16(msg: bytes) -> bytes:
    if not msg:
        return msg
    pad_len = msg[-1]
    if pad_len > 16 or pad_len == 0:
        return msg # No padding or invalid
    # Verify padding
    for i in range(1, pad_len + 1):
        if msg[-i] != pad_len:
            return msg # Invalid padding
    return msg[:-pad_len]
```

**Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_messages.py::test_unpad_random_max16 -v`

**Step 5: Commit**

```bash
git add pywa/client/messages.py tests/unit/test_messages.py
git commit -m "feat: add PKCS7 unpadding utility"
```

---

### Task 4: Handle Incoming Message Nodes

**Files:**
- Modify: `pywa/client/handlers.py` (or wherever business logic handles incoming nodes)
- Modify: `pywa/client/messages.py` 

**Step 1: Add Node Decryption Logic**
Create `parse_message_node` that takes a `<message>` node, finds `<enc>`, extracts `v="2"` and `type`, calls `SignalRepository.decrypt_message()`, unpads the result, and decodes the protobuf `wa_pb2.Message()`.

**Step 2: Emit Decrypted Message Event**
Integrate `parse_message_node` into the event loop. If it's a `pkmsg`, it decrypts and updates the session. If it's a `msg`, it just decrypts. The parsed protobuf structure is emitted to the application.

**Step 3: Test flow**
Write an integration test feeding an incoming `<message>` node and verifying a decrypted `wa_pb2.Message` is produced.

**Step 5: Commit**

```bash
git add pywa/client/
git commit -m "feat: handle and decrypt incoming message nodes"
```
