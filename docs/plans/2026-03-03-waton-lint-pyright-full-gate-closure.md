# Waton Lint + Pyright Full Gate Closure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Menutup seluruh debt lint (Ruff) dan typecheck (Pyright strict) agar preflight parity bisa lulus tanpa `--skip-lint` dan `--skip-typecheck`.

**Architecture:** Eksekusi dilakukan dalam wave kecil berbasis root-cause cluster: (A) error pyright yang block correctness runtime terlebih dulu, (B) aturan lint yang auto-fixable massal untuk menurunkan noise, (C) sisa lint manual per file, (D) verifikasi gate penuh. Tiap wave wajib TDD/verification: tulis/aktifkan test fail dulu untuk bugfix behavior, lalu minimal patch, lalu re-run checks.

**Tech Stack:** Python 3.11, pytest, Ruff, Pyright strict, preflight parity scripts.

---

### Task 1: Establish reproducible baseline and scope guard

**Files:**
- Create: `.tmp/ruff-current.json` (generated)
- Create: `.tmp/pyright-current.json` (generated)
- Modify: `docs/parity/artifacts/lint-type-baseline-2026-03-01.md`
- Test: `tests/unit/test_lint_type_baseline_artifacts.py`

**Step 1: Write the failing test**

```python
from pathlib import Path


def test_current_lint_type_snapshots_exist() -> None:
    assert Path(".tmp/ruff-current.json").exists()
    assert Path(".tmp/pyright-current.json").exists()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_lint_type_baseline_artifacts.py::test_current_lint_type_snapshots_exist -v`
Expected: FAIL (snapshot belum ada).

**Step 3: Write minimal implementation**

Run:
- `python -m ruff check waton tests tools --output-format json > .tmp/ruff-current.json || true`
- `python -m pyright --outputjson > .tmp/pyright-current.json || true`

Update `docs/parity/artifacts/lint-type-baseline-2026-03-01.md` dengan angka terkini:
- Ruff: 216 issues
- Pyright: 35 errors

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_lint_type_baseline_artifacts.py::test_current_lint_type_snapshots_exist -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/unit/test_lint_type_baseline_artifacts.py docs/parity/artifacts/lint-type-baseline-2026-03-01.md
git commit -m "test: refresh lint and pyright baseline snapshots"
```

---

### Task 2: Fix websocket/manual-disconnect semantics regression-proofing

**Files:**
- Modify: `waton/infra/websocket.py`
- Modify: `tests/unit/test_websocket.py`
- Test: `tests/integration/test_reliability_live.py`

**Step 1: Write the failing test**

(If not present) add test ensuring `WebSocketTransport.disconnect()` always triggers `on_disconnect` callback exactly once.

```python
def test_disconnect_emits_on_disconnect_callback() -> None:
    ...
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_websocket.py::test_disconnect_emits_on_disconnect_callback -v`
Expected: FAIL tanpa callback emit.

**Step 3: Write minimal implementation**

Ensure `disconnect()` in `waton/infra/websocket.py` memanggil `on_disconnect` setelah close manual.

**Step 4: Verify**

Run:
- `python -m pytest tests/unit/test_websocket.py -q`
- `WATON_RUN_LIVE_RELIABILITY=1 WATON_LIVE_RECONNECT=0 WATON_AUTH_DB=waton_livedebug.db python -m pytest tests/integration/test_reliability_live.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/infra/websocket.py tests/unit/test_websocket.py
git commit -m "fix: emit disconnect callback on manual websocket close"
```

---

### Task 3: Close all current Pyright errors (35 -> 0)

**Files:**
- Modify: `waton/client/chats.py`
- Modify: `waton/client/communities.py`
- Modify: `waton/client/groups.py`
- Modify: `waton/client/media.py`
- Modify: `waton/client/messages_recv.py`
- Modify: `waton/client/newsletter.py`
- Modify: `waton/client/retry_manager.py`
- Modify: `waton/client/usync.py`
- Modify: `waton/core/entities.py`
- Modify: `waton/core/events.py`
- Modify: `waton/protocol/binary_node.py`
- Modify: `waton/protocol/frame_codec.py`
- Modify: `waton/simple_api.py`
- Modify: `waton/utils/lt_hash.py`
- Modify: `waton/utils/media_utils.py`
- Modify: `waton/utils/preflight.py`
- Test: `tests/unit/test_client.py`, `tests/unit/test_preflight.py`, `tests/unit/test_websocket.py`

**Step 1: Write failing type-focused test command**

Run: `python -m pyright`
Expected: FAIL with 35 errors (rules: `reportUnknown*`, `reportUnnecessaryIsInstance`, `reportPrivateUsage`, `reportArgumentType`, dll).

**Step 2: Write minimal implementation in micro-batches**

Batch 3.1 (safe narrowing / unnecessary checks):
- remove redundant `isinstance(child, BinaryNode)` checks in `_children()` helpers where list is already typed.
- avoid optional chaining on repeated `_find_child(...)` calls by assigning local variable once (`linked_parent = cls._find_child(...)`).

Batch 3.2 (private usage boundary):
- expose public wrappers in `waton/utils/media_utils.py` and `waton/protocol/protobuf/wire.py` (`upload_once`, `verify_remote_checksum`, `iter_fields`) and switch imports/calls accordingly.

Batch 3.3 (typing precision):
- `waton/core/entities.py`: replace `participants: list[...] = None` with `field(default_factory=list)`.
- `waton/core/events.py`: change `list[dict]` to `list[dict[str, Any]]`.
- `waton/utils/preflight.py`: narrow evidence mapping with typed local map before `.get()`.
- `waton/client/retry_manager.py`: avoid `int(error_code)` when `None`; narrow first.
- `waton/client/usync.py`: explicitly type `user_nodes`, `device_list_node` iteration, and sid generation path to avoid protected/private use complaint.

Batch 3.4 (dead/unused):
- remove unused import in `waton/protocol/frame_codec.py`.
- remove unused nested `_dispatch` warning source in `waton/simple_api.py` by explicit suppression-safe pattern (or convert to named handlers referenced directly).

**Step 3: Verify each batch**

Run after each batch:
- `python -m pyright`
- relevant tests (minimum):
  - `python -m pytest tests/unit/test_client.py -q`
  - `python -m pytest tests/unit/test_preflight.py -q`
  - `python -m pytest tests/unit/test_websocket.py -q`

Expected: pyright count drops monotonically until 0; tests remain PASS.

**Step 4: Final verification for task**

Run: `python -m pyright`
Expected: `0 errors`.

**Step 5: Commit**

```bash
git add waton/client/chats.py waton/client/communities.py waton/client/groups.py waton/client/media.py waton/client/messages_recv.py waton/client/newsletter.py waton/client/retry_manager.py waton/client/usync.py waton/core/entities.py waton/core/events.py waton/protocol/binary_node.py waton/protocol/frame_codec.py waton/simple_api.py waton/utils/lt_hash.py waton/utils/media_utils.py waton/utils/preflight.py
git commit -m "fix: close strict pyright debt across client and core modules"
```

---

### Task 4: Apply deterministic Ruff auto-fixes first (high-yield)

**Files:**
- Modify: multiple files under `waton/`, `tests/`, `tools/` (auto-fix result)

**Step 1: Write failing lint command**

Run: `python -m ruff check waton tests tools`
Expected: FAIL (216 issues).

**Step 2: Write minimal implementation (auto-fixable set)**

Run:
- `python -m ruff check waton tests tools --fix`

This should clear most of:
- `I001`, `UP037`, `UP045`, `UP012`, sebagian `TC006`, dll.

**Step 3: Verify reduced lint count**

Run: `python -m ruff check waton tests tools --output-format json`
Expected: issue count turun signifikan; simpan snapshot baru `.tmp/ruff-after-autofix.json`.

**Step 4: Commit**

```bash
git add waton tests tools
git commit -m "style: apply ruff auto-fixes for deterministic lint debt reduction"
```

---

### Task 5: Resolve remaining manual Ruff violations by cluster

**Files:**
- Modify: `waton/app/app.py`, `waton/app/context.py`, `waton/app/filters.py`, `waton/app/router.py`
- Modify: `waton/core/errors.py`, `waton/core/jid.py`, `waton/__init__.py`, `waton/core/__init__.py`, `waton/infra/websocket.py`
- Modify: `tools/dashboard/server.py`, `tools/dashboard/__init__.py`, `tools/dashboard/runtime.py`
- Modify: `tests/unit/test_app.py`, `tests/unit/test_client.py`, `tests/unit/test_usync.py`, `tests/unit/test_messages.py`, dll line-length test files

**Step 1: Write failing focused lint checks per cluster**

Run per cluster, contoh:
- `python -m ruff check waton/app`
- `python -m ruff check waton/core waton/infra`
- `python -m ruff check tools/dashboard`
- `python -m ruff check tests/unit/test_app.py tests/unit/test_client.py tests/unit/test_usync.py tests/unit/test_messages.py`

Expected: FAIL.

**Step 2: Write minimal implementation per rule family**

- `E501`: wrap long lines manually.
- `A004/A001`: alias `ConnectionError` import to non-builtin-shadowing name.
- `ANN202/ANN20x` in dashboard handlers: add explicit return annotations.
- `TC001/TC003` remaining: move type-only imports under `TYPE_CHECKING` where required.
- `W293`: remove trailing whitespace.
- `SIM108/SIM105/B009`: apply direct code simplification without behavior change.

**Step 3: Verify per cluster**

After each cluster:
- run focused `ruff check` cluster.
- run closest tests:
  - app cluster -> `python -m pytest tests/unit/test_app.py -q`
  - core/infra cluster -> `python -m pytest tests/unit/test_websocket.py tests/unit/test_jid.py -q`
  - dashboard cluster -> `python -m pytest tests/unit/test_dashboard.py -q`

**Step 4: Final lint verification**

Run: `python -m ruff check waton tests tools`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton tests tools
git commit -m "chore: resolve remaining manual ruff violations across app core and dashboard"
```

---

### Task 6: Full non-skip gate verification (the actual target)

**Files:**
- Modify: `docs/parity/artifacts/lint-type-baseline-2026-03-01.md`
- Modify: `CHANGELOG.md`

**Step 1: Run complete verification suite**

Run:
```bash
python -m pytest tests -q
python -m ruff check waton tests tools
python -m pyright
python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json
python scripts/parity_evidence_smoke.py --parity-evidence docs/parity/artifacts/strict-evidence-sample.json
```

Expected: all PASS (tanpa skip lint/type).

**Step 2: Update baseline doc + changelog**

- tulis angka final lint/type (target 0/0) di baseline artifact doc.
- catat closure di `CHANGELOG.md`.

**Step 3: Re-run the proving command**

Run again (single command yang jadi bukti akhir):
- `python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json`

Expected: `ALL CHECKS PASSED`.

**Step 4: Commit**

```bash
git add CHANGELOG.md docs/parity/artifacts/lint-type-baseline-2026-03-01.md
git commit -m "chore: achieve full lint+pyright clean parity preflight gate"
```

---

## End-of-Plan Verification Commands

1. `python -m pytest tests -q`
2. `python -m ruff check waton tests tools`
3. `python -m pyright`
4. `python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json`
5. `python scripts/parity_evidence_smoke.py --parity-evidence docs/parity/artifacts/strict-evidence-sample.json`

Expected:
- Semua PASS tanpa skip.
- WhatsApp live-reliability path tetap hijau.
- Parity strict preflight tetap `ALL CHECKS PASSED`.
