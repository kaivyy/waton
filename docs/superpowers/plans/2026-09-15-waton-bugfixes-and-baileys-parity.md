# Waton Bugfixes and Baileys Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all discovered cryptographic bugs, WhatsApp binary protocol discrepancies, missing GroupCipher integration, multi-device session injection errors, and parity test issues to achieve wire interoperability with Baileys and WhatsApp servers.

**Architecture:** 
- Fix low-level cryptographic derivation inversion (`hmac_sha256` key vs data order) in protocol addons, poll votes, and reactions.
- Align binary token codec domain types (`hosted: 128`, `hosted.lid: 129`) and signal storage address suffixes.
- Correct HKDF expansion info strings across all media types (sticker, ptv, ptt, history sync).
- Wire `GroupCipher` (SenderKey) into `SignalRepository.decrypt_message` for incoming `skmsg` and into `MessagesAPI._send_payload` for outgoing group messages with `SenderKeyDistributionMessage`.
- Correct multi-device prekey session caching and ACK stanza structures.
- Implement real MMS `media_conn` IQ query and upload transport.

**Tech Stack:**
- Python 3.11+ (asyncio, httpx, aiosqlite)
- Rust (`waton._crypto` pyo3 extension)
- Protobuf wire models (`waton.proto.*`)
- Upstream references: `repos/Baileys` (v7) and `repos/whatsmeow`

## Global Constraints
- Every code change must adhere to `antislop-code`: no decorative banners (`# ===`), no obvious restatements, no step narration comments, only protocol constraints and RFC/specification rationale.
- Test-driven development: failing test written and verified before implementation for every task.
- Zero regression on existing 360+ unit tests.

---

### Task 1: Fix Cryptographic Derivation for Poll Vote, Reaction, and Message Addons

**Files:**
- Modify: `waton/client/messages.py:81-100`
- Modify: `waton/utils/protocol_message.py:245-255`
- Test: `tests/unit/test_protocol_message.py`
- Test: `tests/unit/test_messages.py`

**Interfaces:**
- Consumes: `waton.utils.crypto.hmac_sha256(key: bytes, data: bytes) -> bytes`
- Produces: Correct 32-byte addon / poll / reaction AES-GCM encryption key matching Baileys `decryptPollVote` and RFC 5869 HKDF standard.

- [ ] **Step 1: Write failing tests for Baileys/WhatsApp-compatible addon key derivation**

```python
# In tests/unit/test_protocol_message.py
def test_derive_addon_keys_matches_baileys_and_rfc5869():
    import hmac, hashlib
    from waton.utils.protocol_message import derive_addon_keys

    message_secret = b"\x01" * 32
    sign = b"test_sign_data\x01"

    # Baileys / RFC 5869: key0 = HMAC(key=32_zeros, data=message_secret)
    # decKey = HMAC(key=key0, data=sign)
    expected_key0 = hmac.new(bytes(32), message_secret, hashlib.sha256).digest()
    expected_deckey = hmac.new(expected_key0, sign, hashlib.sha256).digest()

    actual_deckey = derive_addon_keys(message_secret, sign)
    assert actual_deckey == expected_deckey
```

- [ ] **Step 2: Run test to verify failure**

```bash
pytest tests/unit/test_protocol_message.py -k test_derive_addon_keys_matches_baileys_and_rfc5869
```

- [ ] **Step 3: Implement fix in `messages.py` and `protocol_message.py`**

In `waton/client/messages.py` lines 98-99:
```python
    key0 = hmac_sha256(bytes(32), message_secret)
    return hmac_sha256(key0, sign)
```

In `waton/utils/protocol_message.py` lines 251-252:
```python
    key0 = hmac_sha256(bytes(32), message_secret)
    return hmac_sha256(key0, sign)
```

- [ ] **Step 4: Run test suite to verify fix passes**

```bash
pytest tests/unit/test_protocol_message.py -v
```

- [ ] **Step 5: Commit changes**

```bash
git commit -m "fix(crypto): correct hmac parameter order in addon and poll key derivation"
```

---

### Task 2: Correct AD_JID Domain Enums and Signal Session Suffixes for Hosted Accounts

**Files:**
- Modify: `waton/protocol/binary_codec.py:103-108, 263-270`
- Modify: `waton/protocol/signal_repo.py:25-30`
- Test: `tests/unit/test_binary_codec.py`
- Test: `tests/unit/test_signal.py`

**Interfaces:**
- Consumes: WhatsApp binary protocol Tag `AD_JID` (247) domain spec
- Produces: Correct `domain_type` values (`hosted: 128`, `hosted.lid: 129`) and Signal address normalization (`user_128`, `user_129`).

- [ ] **Step 1: Write failing test for hosted AD_JID encode/decode and signal session key**

```python
# In tests/unit/test_binary_codec.py
def test_ad_jid_hosted_domains():
    from waton.protocol.binary_codec import _write_ad_jid, _read_ad_jid
    import io

    # Test hosted (domain 128)
    buf = bytearray()
    _write_ad_jid("12345", 0, "hosted", buf)
    stream = io.BytesIO(buf[1:])  # skip AD_JID tag
    decoded = _read_ad_jid(stream)
    assert decoded == "12345:0@hosted"

    # Test hosted.lid (domain 129)
    buf2 = bytearray()
    _write_ad_jid("67890", 1, "hosted.lid", buf2)
    stream2 = io.BytesIO(buf2[1:])
    decoded2 = _read_ad_jid(stream2)
    assert decoded2 == "67890:1@hosted.lid"
```

- [ ] **Step 2: Run test to verify failure**

```bash
pytest tests/unit/test_binary_codec.py -k test_ad_jid_hosted_domains
```

- [ ] **Step 3: Update `binary_codec.py` and `signal_repo.py`**

In `waton/protocol/binary_codec.py`:
```python
_DOMAIN_TYPE_MAP = {
    "s.whatsapp.net": 0,
    "lid": 1,
    "hosted": 128,
    "hosted.lid": 129,
}
```
and in `_read_ad_jid`:
```python
    if domain_type == 1:
        server = "lid"
    elif domain_type == 128:
        server = "hosted"
    elif domain_type == 129:
        server = "hosted.lid"
```

In `waton/protocol/signal_repo.py`:
```python
        self._domain_suffix = {
            "s.whatsapp.net": "",
            "lid": "_1",
            "hosted": "_128",
            "hosted.lid": "_129",
        }
```

- [ ] **Step 4: Run tests to verify pass**

```bash
pytest tests/unit/test_binary_codec.py tests/unit/test_signal.py -v
```

- [ ] **Step 5: Commit changes**

```bash
git commit -m "fix(protocol): align hosted domain enums with WhatsApp spec (128/129)"
```

---

### Task 3: Align Media HKDF Key Derivation Mappings

**Files:**
- Modify: `waton/utils/media_utils.py:8-16`
- Modify: `waton/client/media.py:100-110`
- Test: `tests/unit/test_media_reliability.py`
- Test: `tests/unit/test_messages.py`

**Interfaces:**
- Consumes: Media type string (`image`, `sticker`, `video`, `ptv`, `audio`, `ptt`, `document`, `md-msg-hist`)
- Produces: Correct HKDF info string: `f"WhatsApp {hkdf_name} Keys"` matching WhatsApp CDN specification.

- [ ] **Step 1: Write failing test verifying media HKDF key mappings**

```python
# In tests/unit/test_media_reliability.py
def test_derive_media_keys_mapping():
    from waton.utils.media_utils import derive_media_keys

    key = b"\x03" * 32
    # sticker must expand with "WhatsApp Image Keys"
    keys_sticker = derive_media_keys(key, "sticker")
    keys_image = derive_media_keys(key, "image")
    assert keys_sticker["cipher_key"] == keys_image["cipher_key"]

    # ptv must expand with "WhatsApp Video Keys"
    keys_ptv = derive_media_keys(key, "ptv")
    keys_video = derive_media_keys(key, "video")
    assert keys_ptv["cipher_key"] == keys_video["cipher_key"]

    # ptt must expand with "WhatsApp Audio Keys"
    keys_ptt = derive_media_keys(key, "ptt")
    keys_audio = derive_media_keys(key, "audio")
    assert keys_ptt["cipher_key"] == keys_audio["cipher_key"]
```

- [ ] **Step 2: Run test to verify failure**

```bash
pytest tests/unit/test_media_reliability.py -k test_derive_media_keys_mapping
```

- [ ] **Step 3: Implement `MEDIA_HKDF_KEY_MAPPING` in `media_utils.py` and `media.py`**

```python
MEDIA_HKDF_KEY_MAPPING: dict[str, str] = {
    "image": "Image",
    "sticker": "Image",
    "document": "Document",
    "video": "Video",
    "ptv": "Video",
    "gif": "Video",
    "audio": "Audio",
    "ptt": "Audio",
    "history": "History",
    "md-msg-hist": "History",
    "md-app-state": "App State",
}

def derive_media_keys(media_key: bytes, media_type: str) -> dict[str, bytes]:
    type_label = MEDIA_HKDF_KEY_MAPPING.get(media_type, media_type.capitalize())
    info = f"WhatsApp {type_label} Keys".encode()
    expanded = hkdf(media_key, 112, bytes(32), info)
    return {
        "iv": expanded[:16],
        "cipher_key": expanded[16:48],
        "mac_key": expanded[48:80],
        "ref_key": expanded[80:112],
    }
```

- [ ] **Step 4: Run tests to verify pass**

```bash
pytest tests/unit/test_media_reliability.py tests/unit/test_messages.py -v
```

- [ ] **Step 5: Commit changes**

```bash
git commit -m "fix(media): align media HKDF key mappings with WhatsApp specification"
```

---

### Task 4: Integrate Group Messaging (`GroupCipher` & `SenderKeyDistributionMessage`)

**Files:**
- Modify: `waton/protocol/signal_repo.py` (add `decrypt_group_message`, `encrypt_group_message`, handle `type_str == "skmsg"`)
- Modify: `waton/client/messages_recv.py` (pass group JID and participant into group decryption, process incoming `senderKeyDistributionMessage`)
- Modify: `waton/client/messages.py` (in `_send_payload`, detect `@g.us`, encrypt group payload via `GroupCipher`, attach `senderKeyDistributionMessage` when needed)
- Test: `tests/unit/test_group_signal.py`
- Test: `tests/unit/test_messages.py`

**Interfaces:**
- Consumes: `GroupCipher` from `waton.protocol.group_cipher`
- Produces: Wire-compatible group message stanza `<message to="group@g.us"><enc type="skmsg">...</enc></message>` and decryption of incoming group nodes.

- [ ] **Step 1: Write failing tests for group message decryption and sender key distribution**

```python
# In tests/unit/test_group_signal.py
@pytest.mark.asyncio
async def test_signal_repo_decrypt_skmsg_with_group_cipher():
    # Simulate incoming skmsg node decryption through SignalRepository
    repo = SignalRepository(creds=mock_creds, storage=FakeStorage())
    # decrypting skmsg should not raise ValueError("Unknown message type: skmsg")
    ...
```

- [ ] **Step 2: Run test to verify failure**

```bash
pytest tests/unit/test_group_signal.py -k test_signal_repo_decrypt_skmsg_with_group_cipher
```

- [ ] **Step 3: Implement GroupCipher integration in `SignalRepository`, `messages_recv.py`, and `messages.py`**

1. In `SignalRepository`:
   - Add `async def decrypt_group_message(self, group_jid: str, author_jid: str, ciphertext: bytes) -> bytes`
   - In `decrypt_message`, when `type_str == "skmsg"`, delegate to `decrypt_group_message`.
2. In `messages_recv.py`:
   - In `_extract_message_payload`, identify if the node has group chat context (`remote_jid.endswith("@g.us")` or `node.attrs.get("participant")`) and pass it to decryption.
   - When decoding decrypted payload, inspect for `senderKeyDistributionMessage` and call `group_cipher.process_sender_key_distribution`.
3. In `messages.py`:
   - In `_send_payload`, when `target_jid.endswith("@g.us")`:
     - Encrypt the plaintext using `GroupCipher(target_jid, self.client.storage).encrypt(me_jid, padded_payload)`.
     - Check if participants need `SenderKeyDistributionMessage` (or broadcast 1:1 to new devices if required).
     - Emit `<message to="group@g.us"><enc type="skmsg" v="2">ciphertext</enc></message>`.

- [ ] **Step 4: Run tests to verify pass**

```bash
pytest tests/unit/test_group_signal.py tests/unit/test_messages.py -v
```

- [ ] **Step 5: Commit changes**

```bash
git commit -m "feat(group): integrate GroupCipher and sender key distribution for group messaging"
```

---

### Task 5: Fix Multi-Device Prekey Injection and Stanza ACK Senders

**Files:**
- Modify: `waton/client/messages.py:980-995`
- Modify: `waton/client/messages_recv.py:791-804`
- Test: `tests/unit/test_messages.py`
- Test: `tests/unit/test_client.py`

**Interfaces:**
- Consumes: USync device query results and incoming stanza ACK attributes.
- Produces: Device-isolated session initialization and RFC-compliant stanza ACK containing `from`.

- [ ] **Step 1: Write failing test for device-specific session injection and ACK `from` attribute**

```python
# In tests/unit/test_messages.py
def test_build_message_ack_includes_from_when_provided():
    from waton.client.messages_recv import build_message_ack
    from waton.protocol.binary_node import BinaryNode

    node = BinaryNode(tag="message", attrs={"from": "1234@s.whatsapp.net", "id": "ABC"})
    ack = build_message_ack(node, me_jid="me@s.whatsapp.net")
    assert ack.attrs.get("from") == "me@s.whatsapp.net"
```

- [ ] **Step 2: Run test to verify failure**

```bash
pytest tests/unit/test_messages.py -k test_build_message_ack_includes_from_when_provided
```

- [ ] **Step 3: Implement device session isolation and ACK `from` attribute**

In `waton/client/messages.py`: Ensure `_parse_and_inject_sessions` maps identity and prekeys to the specific device JID requested, rather than splashing the identical session across all sibling devices.
In `waton/client/messages_recv.py`: Update `build_message_ack` to accept `me_jid: str | None = None` and include `attrs["from"] = me_jid` when provided.

- [ ] **Step 4: Run tests to verify pass**

```bash
pytest tests/unit/test_messages.py tests/unit/test_client.py -v
```

- [ ] **Step 5: Commit changes**

```bash
git commit -m "fix(messages): isolate multi-device prekey sessions and add from attribute to ACKs"
```

---

### Task 6: Resolve Parity Scan Hardcoded Paths and Test Suite Baselines

**Files:**
- Modify: `tests/unit/test_parity_scan.py`
- Test: `tests/unit/test_parity_scan.py`
- Test: `tests/unit/test_lint_type_baseline_artifacts.py`

**Interfaces:**
- Consumes: Workspace relative paths to `waton/` and `repos/Baileys/src`
- Produces: 100% passing test suite across all environments (Linux/Windows/CI).

- [ ] **Step 1: Run `test_parity_scan.py` to confirm current failure**

```bash
pytest tests/unit/test_parity_scan.py -v
```

- [ ] **Step 2: Replace hardcoded Windows paths with dynamic project root paths**

In `tests/unit/test_parity_scan.py`:
```python
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
WATON_ROOT = str(ROOT / "waton")
BAILEYS_SRC = str(ROOT / "repos" / "Baileys" / "src")
```

- [ ] **Step 3: Run full unit test suite**

```bash
pytest tests/unit/ -v
```

- [ ] **Step 4: Verify 100% of unit tests pass**

- [ ] **Step 5: Commit changes**

```bash
git commit -m "test: make parity scan paths dynamic and ensure all unit tests pass"
```

---

### Task 7: Implement Real WhatsApp MMS Media Connection (`media_conn`) and Upload

**Files:**
- Create: `waton/client/media_upload.py`
- Modify: `waton/client/media.py`
- Modify: `waton/utils/media_utils.py`
- Test: `tests/unit/test_media_upload.py`

**Interfaces:**
- Consumes: `WAClient.query(tag='iq', xmlns='w:m')`
- Produces: Valid direct path and media URL from `https://mmg.whatsapp.net` hosts using streaming upload with auth token.

- [ ] **Step 1: Write unit tests with mocked HTTP transport for `refresh_media_conn` and `upload_media_to_server`**

```python
# In tests/unit/test_media_upload.py
@pytest.mark.asyncio
async def test_refresh_media_conn_queries_iq_and_caches():
    ...
```

- [ ] **Step 2: Run test to verify failure**

```bash
pytest tests/unit/test_media_upload.py
```

- [ ] **Step 3: Implement `MediaConnectionManager` and real upload client**

- Query `<iq type="set" xmlns="w:m" to="s.whatsapp.net"><media_conn/></iq>`.
- Parse response node containing `host` list, `auth` token, and `ttl`.
- Implement streaming POST to `https://{hostname}{MEDIA_PATH_MAP[media_type]}/{fileEncSha256B64}?auth={auth}&token={fileEncSha256B64}`.
- Parse JSON response returning `url` and `direct_path`.

- [ ] **Step 4: Run tests to verify pass**

```bash
pytest tests/unit/test_media_upload.py -v
```

- [ ] **Step 5: Commit changes**

```bash
git commit -m "feat(media): implement WhatsApp MMS media_conn query and upload transport"
```
