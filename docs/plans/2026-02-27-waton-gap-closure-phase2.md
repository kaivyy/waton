# Waton Gap Closure Phase 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close the highest-impact verified gaps versus Baileys (chat modify stub, placeholder resend runtime wiring, and pip package hygiene).

**Architecture:** Keep protocol boundaries clean by implementing missing runtime behaviors in existing client modules (`ChatsAPI`, `WAClient`, receive helpers) and avoiding broad refactors. Package hygiene is handled in build metadata so runtime code remains unaffected.

**Tech Stack:** Python 3.11+, asyncio, pytest, maturin/Cargo packaging metadata.

---

### Task 1: Replace `chat_modify` Stub With Real Action Nodes

**Files:**
- Modify: `waton/client/chats.py`
- Modify: `tests/unit/test_chats.py`

**Step 1: Write failing tests**
- Add tests for supported actions: `archive`, `unarchive`, `pin`, `unpin`, `mute`, `unmute`, `read`, `unread`.
- Assert `chat_modify` sends an IQ/query node with deterministic action tags/attrs.
- Add test that unsupported actions raise `ValueError`.

**Step 2: Run tests to verify fail**
- Run: `python -m pytest tests/unit/test_chats.py -q`

**Step 3: Minimal implementation**
- Implement action mapping in `chat_modify`.
- Build/send query node through `client.query` (or `send_node` where appropriate).

**Step 4: Run tests to verify pass**
- Run: `python -m pytest tests/unit/test_chats.py -q`

---

### Task 2: Wire Placeholder Resend Request Into Retry Runtime

**Files:**
- Modify: `waton/client/client.py`
- Modify: `waton/defaults/config.py`
- Modify: `tests/unit/test_client.py`

**Step 1: Write failing tests**
- Add test: on decrypt failure, when enabled, client emits placeholder resend IQ.
- Add test: config flag disables placeholder request while preserving retry receipt.
- Add test: retry-request handling attempts placeholder request for message IDs.

**Step 2: Run tests to verify fail**
- Run: `python -m pytest tests/unit/test_client.py -q`

**Step 3: Minimal implementation**
- Add config gate(s), e.g. `enable_placeholder_resend`, `placeholder_resend_on_retry`.
- In `_handle_incoming_error` and/or retry-request flow, call `build_placeholder_resend_request`.
- Record send outcome in emitted event payload for observability.

**Step 4: Run tests to verify pass**
- Run: `python -m pytest tests/unit/test_client.py -q`

---

### Task 3: Exclude Non-Essential Files From `pip install waton`

**Files:**
- Modify: `Cargo.toml`
- Modify: `README.md`
- Modify: `docs/runbooks/parity-release-checklist.md`

**Step 1: Write failing/validation checks first**
- Add a verification command sequence in docs and local check:
  - Build wheel/sdist.
  - Inspect archive listing to ensure `docs/`, `examples/`, `tests/`, `tools/` are not shipped.

**Step 2: Run checks to capture current state**
- Run:
  - `python -m pip wheel . --no-deps -w .tmp-wheel`
  - `python -m pip download . --no-binary :all: -d .tmp-sdist`
- Inspect entries.

**Step 3: Implement packaging exclusion**
- Add `exclude` patterns in Cargo package metadata to prune non-runtime assets.
- Keep required files (`waton/`, `pyproject.toml`, `Cargo.toml`, license/readme) intact.

**Step 4: Re-run build/inspection checks**
- Confirm excluded folders are absent from built artifacts.

---

### Task 4: Documentation and Release Traceability

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `docs/parity/baileys-parity-baseline.json` (if changed by scan)

**Step 1: Update docs/changelog**
- Document:
  - `chat_modify` implementation status,
  - placeholder resend runtime behavior and config flags,
  - packaging exclusion behavior.

**Step 2: Final verification**
- Run:
  - `python -m pytest tests -q`
  - `python -m tools.parity.scan_baileys_parity --waton waton --baileys C:\\Users\\Arvy Kairi\\Desktop\\whatsapp\\Baileys\\src --out docs/parity/baileys-parity-latest.json`
  - `python scripts/preflight_check.py --skip-lint --skip-typecheck`

**Step 3: Baseline sync**
- If needed:
  - copy `docs/parity/baileys-parity-latest.json` -> `docs/parity/baileys-parity-baseline.json`
