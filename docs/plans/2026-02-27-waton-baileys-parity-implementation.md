# Waton Baileys Parity Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver Waton behavioral parity with Baileys core reliability domains (receive, app-state sync, retry, group signal, identity/media hardening) with clean architecture and maintainable code.

**Architecture:** Add missing reliability components as explicit modules in `waton/client` and `waton/protocol`, keep protocol/persistence boundaries strict, and enforce `persist-before-emit` and deterministic recovery semantics. Use parity tests and live integration gates to prove no behavioral gap for core flows.

**Tech Stack:** Python 3.11+, asyncio, SQLite (`aiosqlite`), Rust PyO3 crypto extension, pytest, ruff, pyright.

---

## Prerequisites

1. Work from dedicated worktree for parity implementation.
2. Keep source-of-truth comparison target at `C:\Users\Arvy Kairi\Desktop\whatsapp\Baileys\src`.
3. Apply @test-driven-development on each task and @verification-before-completion before each completion claim.

### Task 1: Build Parity Scanner Baseline

**Files:**
- Create: `tools/parity/scan_baileys_parity.py`
- Create: `tests/unit/test_parity_scan.py`
- Create: `docs/parity/baileys-parity-baseline.json`

**Step 1: Write the failing test**

```python
from tools.parity.scan_baileys_parity import scan_parity

def test_parity_scan_reports_core_domains() -> None:
    report = scan_parity(
        waton_root=r"C:\Users\Arvy Kairi\Desktop\whatsapp\waton\waton",
        baileys_src=r"C:\Users\Arvy Kairi\Desktop\whatsapp\Baileys\src",
    )
    assert "messages-recv" in report["domains"]
    assert "app-state-sync" in report["domains"]
    assert "retry-manager" in report["domains"]
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_parity_scan.py::test_parity_scan_reports_core_domains -v`  
Expected: FAIL with import/module not found.

**Step 3: Write minimal implementation**

```python
def scan_parity(waton_root: str, baileys_src: str) -> dict:
    return {
        "domains": {
            "messages-recv": {"status": "missing"},
            "app-state-sync": {"status": "missing"},
            "retry-manager": {"status": "missing"},
        }
    }
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_parity_scan.py::test_parity_scan_reports_core_domains -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add tools/parity/scan_baileys_parity.py tests/unit/test_parity_scan.py docs/parity/baileys-parity-baseline.json
git commit -m "test: add parity scanner baseline for waton vs baileys"
```

### Task 2: Implement Receive Dispatcher Module

**Files:**
- Create: `waton/client/messages_recv.py`
- Modify: `waton/client/client.py`
- Test: `tests/unit/test_messages_recv.py`

**Step 1: Write the failing test**

```python
from waton.client.messages_recv import classify_incoming_node
from waton.protocol.binary_node import BinaryNode

def test_classify_message_node() -> None:
    node = BinaryNode(tag="message", attrs={"id": "1"}, content=[])
    assert classify_incoming_node(node) == "message"
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_messages_recv.py::test_classify_message_node -v`  
Expected: FAIL (module/classifier missing)

**Step 3: Write minimal implementation**

```python
def classify_incoming_node(node: BinaryNode) -> str:
    if node.tag == "message":
        return "message"
    if node.tag == "receipt":
        return "receipt"
    if node.tag == "notification":
        return "notification"
    return "other"
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_messages_recv.py::test_classify_message_node -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/client/messages_recv.py waton/client/client.py tests/unit/test_messages_recv.py
git commit -m "feat: add inbound message dispatcher classification"
```

### Task 3: Decrypt + Normalize Incoming Encrypted Message

**Files:**
- Modify: `waton/client/messages_recv.py`
- Modify: `waton/client/client.py`
- Modify: `waton/protocol/signal_repo.py`
- Test: `tests/unit/test_messages_recv.py`

**Step 1: Write the failing test**

```python
def test_decrypt_and_normalize_enc_message(monkeypatch) -> None:
    # mocked decrypt returns WAProto bytes for conversation="hi"
    event = decode_incoming_message_node(enc_node, fake_repo)
    assert event["type"] == "messages.upsert"
    assert event["message"]["text"] == "hi"
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_messages_recv.py::test_decrypt_and_normalize_enc_message -v`  
Expected: FAIL (decode_incoming_message_node missing)

**Step 3: Write minimal implementation**

```python
async def decode_incoming_message_node(node: BinaryNode, signal_repo: SignalRepository) -> dict:
    plaintext = await signal_repo.decrypt_message_node(node)
    parsed = wa_pb2.Message()
    parsed.ParseFromString(_unpad_random_max16(plaintext))
    return {"type": "messages.upsert", "message": {"text": parsed.conversation}}
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_messages_recv.py::test_decrypt_and_normalize_enc_message -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/client/messages_recv.py waton/client/client.py waton/protocol/signal_repo.py tests/unit/test_messages_recv.py
git commit -m "feat: decrypt and normalize inbound encrypted messages"
```

### Task 4: Enforce Persist-Before-Emit Event Order

**Files:**
- Create: `waton/client/event_pipeline.py`
- Modify: `waton/client/client.py`
- Modify: `waton/infra/storage_sqlite.py`
- Test: `tests/unit/test_event_pipeline.py`

**Step 1: Write the failing test**

```python
def test_persist_happens_before_emit() -> None:
    calls = []
    pipeline = EventPipeline(save_fn=lambda _: calls.append("save"), emit_fn=lambda _: calls.append("emit"))
    pipeline.process({"type": "messages.upsert"})
    assert calls == ["save", "emit"]
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_event_pipeline.py::test_persist_happens_before_emit -v`  
Expected: FAIL (pipeline missing)

**Step 3: Write minimal implementation**

```python
class EventPipeline:
    def __init__(self, save_fn, emit_fn):
        self._save_fn = save_fn
        self._emit_fn = emit_fn

    async def process(self, event: dict) -> None:
        await self._save_fn(event)
        await self._emit_fn(event)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_event_pipeline.py::test_persist_happens_before_emit -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/client/event_pipeline.py waton/client/client.py waton/infra/storage_sqlite.py tests/unit/test_event_pipeline.py
git commit -m "feat: enforce persist-before-emit event pipeline"
```

### Task 5: Implement App-State Patch Engine + Real LT Hash

**Files:**
- Create: `waton/protocol/app_state.py`
- Modify: `waton/utils/lt_hash.py`
- Modify: `waton/client/client.py`
- Test: `tests/unit/test_app_state.py`
- Test: `tests/unit/test_lt_hash.py`

**Step 1: Write the failing tests**

```python
def test_apply_patch_updates_version_and_hash() -> None:
    state = {"version": 1, "hash": b"\x00" * 32}
    out = apply_patch(state, {"op": "set", "key": "chat:1", "value": "x"})
    assert out["version"] == 2
    assert out["hash"] != state["hash"]
```

```python
def test_lt_hash_matches_expected_vector() -> None:
    assert compute_lt_hash([b"a", b"b"]) == bytes.fromhex("...")
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_app_state.py tests/unit/test_lt_hash.py -v`  
Expected: FAIL (module/stub behavior)

**Step 3: Write minimal implementation**

```python
def apply_patch(state: dict, patch: dict) -> dict:
    items = dict(state.get("items", {}))
    if patch["op"] == "set":
        items[patch["key"]] = patch["value"]
    version = int(state["version"]) + 1
    new_hash = compute_lt_hash([f"{k}:{v}".encode() for k, v in sorted(items.items())])
    return {"items": items, "version": version, "hash": new_hash}
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_app_state.py tests/unit/test_lt_hash.py -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/protocol/app_state.py waton/utils/lt_hash.py waton/client/client.py tests/unit/test_app_state.py tests/unit/test_lt_hash.py
git commit -m "feat: add deterministic app-state patch engine and real lt-hash"
```

### Task 6: Add Retry Manager with Idempotency

**Files:**
- Create: `waton/client/retry_manager.py`
- Modify: `waton/client/messages.py`
- Modify: `waton/client/client.py`
- Test: `tests/unit/test_retry_manager.py`

**Step 1: Write the failing test**

```python
def test_retry_manager_avoids_duplicate_send() -> None:
    mgr = RetryManager(max_attempts=3)
    assert mgr.should_send("msg-1") is True
    assert mgr.should_send("msg-1") is False
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_retry_manager.py::test_retry_manager_avoids_duplicate_send -v`  
Expected: FAIL (RetryManager missing)

**Step 3: Write minimal implementation**

```python
class RetryManager:
    def __init__(self, max_attempts: int = 3) -> None:
        self.max_attempts = max_attempts
        self.sent: set[str] = set()

    def should_send(self, message_id: str) -> bool:
        if message_id in self.sent:
            return False
        self.sent.add(message_id)
        return True
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_retry_manager.py::test_retry_manager_avoids_duplicate_send -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/client/retry_manager.py waton/client/messages.py waton/client/client.py tests/unit/test_retry_manager.py
git commit -m "feat: add retry manager with idempotency guard"
```

### Task 7: Replace Group Signal Stubs

**Files:**
- Modify: `waton/protocol/group_cipher.py`
- Modify: `waton/protocol/signal_repo.py`
- Modify: `rust/src/signal.rs`
- Modify: `rust/src/lib.rs`
- Test: `tests/unit/test_group_signal.py`

**Step 1: Write the failing test**

```python
async def test_group_cipher_roundtrip_no_stub_values(storage) -> None:
    gc = GroupCipher("123@g.us", storage)
    ct = await gc.encrypt("111@s.whatsapp.net", b"hello")
    pt = await gc.decrypt("111@s.whatsapp.net", ct)
    assert pt == b"hello"
    assert b"stub" not in ct
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_group_signal.py::test_group_cipher_roundtrip_no_stub_values -v`  
Expected: FAIL (stub output)

**Step 3: Write minimal implementation**

```python
async def encrypt(self, sender_jid: str, plaintext: bytes) -> bytes:
    sender_key = await self._load_or_create_sender_key(sender_jid)
    ciphertext, next_key = group_encrypt(sender_key, plaintext)
    await self.storage.save_sender_key(self.group_jid, sender_jid, next_key)
    return ciphertext
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_group_signal.py::test_group_cipher_roundtrip_no_stub_values -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/protocol/group_cipher.py waton/protocol/signal_repo.py rust/src/signal.rs rust/src/lib.rs tests/unit/test_group_signal.py
git commit -m "feat: implement non-stub group signal sender-key flow"
```

### Task 8: Add Identity-Change Handler

**Files:**
- Create: `waton/client/identity_change_handler.py`
- Modify: `waton/client/client.py`
- Test: `tests/unit/test_identity_change_handler.py`

**Step 1: Write the failing test**

```python
def test_identity_change_marks_session_stale() -> None:
    state = {"session_stale": False}
    out = handle_identity_change(state, jid="123@s.whatsapp.net")
    assert out["session_stale"] is True
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_identity_change_handler.py::test_identity_change_marks_session_stale -v`  
Expected: FAIL (handler missing)

**Step 3: Write minimal implementation**

```python
def handle_identity_change(state: dict, jid: str) -> dict:
    out = dict(state)
    out["session_stale"] = True
    out["stale_jid"] = jid
    return out
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_identity_change_handler.py::test_identity_change_marks_session_stale -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/client/identity_change_handler.py waton/client/client.py tests/unit/test_identity_change_handler.py
git commit -m "feat: add identity change handling policy"
```

### Task 9: Harden Media Upload/Download Reliability

**Files:**
- Modify: `waton/client/media.py`
- Modify: `waton/utils/media_utils.py`
- Test: `tests/unit/test_media_reliability.py`

**Step 1: Write the failing test**

```python
def test_upload_retries_and_verifies_checksum(monkeypatch) -> None:
    result = upload_with_retry(b"abc", max_attempts=3)
    assert result["attempts"] >= 1
    assert result["verified"] is True
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_media_reliability.py::test_upload_retries_and_verifies_checksum -v`  
Expected: FAIL (function missing)

**Step 3: Write minimal implementation**

```python
def upload_with_retry(data: bytes, max_attempts: int = 3) -> dict:
    for attempt in range(1, max_attempts + 1):
        url = _upload_once(data)
        if _verify_remote_checksum(url, data):
            return {"url": url, "attempts": attempt, "verified": True}
    raise RuntimeError("upload failed after retries")
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_media_reliability.py::test_upload_retries_and_verifies_checksum -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/client/media.py waton/utils/media_utils.py tests/unit/test_media_reliability.py
git commit -m "feat: add media retry and checksum verification flow"
```

### Task 10: Remove Placeholder API Returns

**Files:**
- Modify: `waton/client/groups.py`
- Modify: `waton/client/communities.py`
- Modify: `waton/client/newsletter.py`
- Test: `tests/unit/test_groups.py`
- Test: `tests/unit/test_communities.py`
- Test: `tests/unit/test_newsletter.py`

**Step 1: Write the failing tests**

```python
def test_group_create_does_not_return_stub(client) -> None:
    gid = run(group_api.create("g", ["1@s.whatsapp.net"]))
    assert "stub" not in gid
```

```python
def test_newsletter_create_does_not_return_stub(client) -> None:
    nid = run(newsletter_api.create("name"))
    assert "stub" not in nid
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/unit/test_groups.py tests/unit/test_communities.py tests/unit/test_newsletter.py -v`  
Expected: FAIL (stub returns)

**Step 3: Write minimal implementation**

```python
response = await self.client.query(node)
jid = response.attrs.get("jid") or self._extract_created_jid(response)
if not jid:
    raise ValueError("create response missing jid")
return jid
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_groups.py tests/unit/test_communities.py tests/unit/test_newsletter.py -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add waton/client/groups.py waton/client/communities.py waton/client/newsletter.py tests/unit/test_groups.py tests/unit/test_communities.py tests/unit/test_newsletter.py
git commit -m "feat: replace stub API returns with protocol-derived IDs"
```

### Task 11: Add Live Parity Reliability Tests

**Files:**
- Create: `tests/integration/test_reliability_live.py`
- Modify: `examples/live_connect.py`
- Modify: `pyproject.toml`

**Step 1: Write the failing test**

```python
import os
import pytest

@pytest.mark.skipif(os.getenv("WATON_RUN_LIVE_RELIABILITY") != "1", reason="live only")
async def test_live_send_receive_reconnect_cycle() -> None:
    assert False, "replace with real live cycle assertions"
```

**Step 2: Run test to verify it fails (when enabled)**

Run: `WATON_RUN_LIVE_RELIABILITY=1 python -m pytest tests/integration/test_reliability_live.py -v`  
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# pair/connect, send text, wait receipt, force reconnect, send again, assert both cycles pass
assert first_cycle_ok is True
assert second_cycle_ok is True
```

**Step 4: Run test to verify it passes**

Run: `WATON_RUN_LIVE_RELIABILITY=1 python -m pytest tests/integration/test_reliability_live.py -v`  
Expected: PASS

**Step 5: Commit**

```bash
git add tests/integration/test_reliability_live.py examples/live_connect.py pyproject.toml
git commit -m "test: add live reliability parity integration cycle"
```

### Task 12: Final Parity Gate + Docs + Changelog

**Files:**
- Modify: `docs/plans/2026-02-27-waton-baileys-parity-design.md`
- Modify: `docs/parity/baileys-parity-baseline.json`
- Modify: `CHANGELOG.md`
- Create: `docs/runbooks/parity-release-checklist.md`

**Step 1: Write failing gate test**

```python
from tools.parity.scan_baileys_parity import scan_parity

def test_critical_parity_domains_are_done() -> None:
    report = scan_parity(...)
    for name in ["messages-recv", "app-state-sync", "retry-manager", "group-signal"]:
        assert report["domains"][name]["status"] == "done"
```

**Step 2: Run test to verify it fails initially**

Run: `python -m pytest tests/unit/test_parity_scan.py::test_critical_parity_domains_are_done -v`  
Expected: FAIL until all core domains are complete.

**Step 3: Write minimal implementation for gate/report sync**

```python
def update_domain(report: dict, name: str, done: bool) -> None:
    report["domains"][name]["status"] = "done" if done else "partial"
```

**Step 4: Run full verification**

Run: `python -m pytest tests -q`  
Expected: PASS  

Run: `python -m ruff check waton tests tools`  
Expected: PASS  

Run: `python -m pyright`  
Expected: PASS

**Step 5: Commit**

```bash
git add docs/plans/2026-02-27-waton-baileys-parity-design.md docs/parity/baileys-parity-baseline.json docs/runbooks/parity-release-checklist.md CHANGELOG.md tests/unit/test_parity_scan.py tools/parity/scan_baileys_parity.py
git commit -m "docs: enforce parity release gates and changelog policy"
```

## Verification Commands (End of Plan)

1. `python -m pytest tests -q`
2. `python -m ruff check waton tests tools`
3. `python -m pyright`
4. `python tools/parity/scan_baileys_parity.py --waton waton --baileys ..\\Baileys\\src --out docs/parity/baileys-parity-baseline.json`

Expected:
- Critical parity domains marked `done`
- No stub marker in critical paths
- All tests/lint/type checks pass

## Notes on "No Difference" Requirement

Because Waton (Python/Rust) and Baileys (TypeScript) are different stacks, file-by-file equality is not a valid target.  
This plan defines "no difference" as **no behavioral gap in critical reliability domains** backed by tests and parity scanner output.
