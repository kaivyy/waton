# Hybrid Supremacy (Phase A + Phase B) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Menaikkan Waton agar unggul terukur atas baseline Baileys pada DX + reliability, serta menutup gap fitur prioritas (Business, WAUSync breadth, WMex wrapper, WAM subset).

**Architecture:** Eksekusi dibagi dua fase. Phase A mem-hardening jalur runtime yang sudah ada dan memperkuat API sederhana. Phase B menambah modul baru yang menutup gap domain Baileys secara targeted tanpa over-engineering. Semua perubahan wajib TDD, dengan commit kecil per domain.

**Tech Stack:** Python 3.11, pytest, Sphinx, existing Waton runtime + Rust extension (maturin develop).

---

### Task 1: Baseline reliability guardrails + failing tests

**Files:**
- Modify: `tests/unit/test_client.py`
- Modify: `tests/unit/test_messages.py`
- Modify: `tests/unit/test_messages_recv.py`
- Modify: `tests/unit/test_app.py`

**Step 1: Write the failing tests**

Tambahkan test baru untuk:
- deterministic retry/decrypt event fields,
- side-effect persistence boundaries,
- no-duplicate protocol side effects,
- stable fallback routing pada incoming edge case.

**Step 2: Run test to verify it fails**

Run:
`python -m pytest tests/unit/test_client.py tests/unit/test_messages.py tests/unit/test_messages_recv.py tests/unit/test_app.py -q`

Expected: FAIL pada test baru (membuktikan behavior belum dipenuhi).

**Step 3: Write minimal implementation**

Patch minimal di runtime core untuk memenuhi assertion test baru.

**Step 4: Run test to verify it passes**

Run command yang sama.
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/unit/test_client.py tests/unit/test_messages.py tests/unit/test_messages_recv.py tests/unit/test_app.py waton/client/client.py waton/client/messages_recv.py waton/utils/process_message.py
git commit -m "fix(runtime): harden deterministic retry and incoming normalization"
```

### Task 2: DX hardening for simple callback API

**Files:**
- Modify: `waton/simple_api.py`
- Modify: `waton/__init__.py`
- Modify: `tests/unit/test_simple_api.py`
- Modify: `README.md`
- Modify: `docs/source/content/getting-started.rst`

**Step 1: Write the failing tests**

Tambahkan test untuk:
- lifecycle callback stability,
- message wrapper consistency,
- explicit error surface saat misuse.

**Step 2: Run test to verify it fails**

Run:
`python -m pytest tests/unit/test_simple_api.py -q`
Expected: FAIL.

**Step 3: Write minimal implementation**

- Tambah guardrails dan callback handling minimal di simple API.
- Perbarui docs snippet agar konsisten dengan behavior real.

**Step 4: Run test to verify it passes**

Run:
`python -m pytest tests/unit/test_simple_api.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/simple_api.py waton/__init__.py tests/unit/test_simple_api.py README.md docs/source/content/getting-started.rst
git commit -m "feat(dx): harden simple callback API lifecycle and docs"
```

### Task 3: Add Business API surface (targeted)

**Files:**
- Create: `waton/client/business.py`
- Modify: `waton/client/client.py`
- Modify: `waton/client/__init__.py`
- Create: `tests/unit/test_business.py`
- Modify: `docs/source/content/business-and-newsletters.rst`

**Step 1: Write the failing tests**

Tambah test minimal untuk business profile fetch/update dan query envelope validation.

**Step 2: Run test to verify it fails**

Run:
`python -m pytest tests/unit/test_business.py -q`
Expected: FAIL (module/API belum ada).

**Step 3: Write minimal implementation**

- Implement `BusinessAPI` dengan subset penting (profile/read-update).
- Wire ke `WAClient` seperti API domain lain.

**Step 4: Run test to verify it passes**

Run:
`python -m pytest tests/unit/test_business.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/client/business.py waton/client/client.py waton/client/__init__.py tests/unit/test_business.py docs/source/content/business-and-newsletters.rst
git commit -m "feat(business): add targeted business API surface"
```

### Task 4: Expand WAUSync protocol breadth

**Files:**
- Modify: `waton/client/usync.py`
- Create: `tests/unit/test_usync.py`
- Modify: `docs/source/content/core-concepts.rst`

**Step 1: Write the failing tests**

Tambah test untuk contact/status/lid/disappearing-mode protocol blocks.

**Step 2: Run test to verify it fails**

Run:
`python -m pytest tests/unit/test_usync.py -q`
Expected: FAIL.

**Step 3: Write minimal implementation**

Tambah protocol builders dan parser response minimal sesuai kebutuhan domain.

**Step 4: Run test to verify it passes**

Run:
`python -m pytest tests/unit/test_usync.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/client/usync.py tests/unit/test_usync.py docs/source/content/core-concepts.rst
git commit -m "feat(usync): add multi-protocol query coverage"
```

### Task 5: Add WMex wrapper (minimal but production-safe)

**Files:**
- Create: `waton/client/mex.py`
- Modify: `waton/client/client.py`
- Create: `tests/unit/test_mex.py`
- Modify: `docs/source/content/client-api-reference.rst`

**Step 1: Write the failing tests**

Tambah test untuk envelope/query build dan response normalization pada mex wrapper.

**Step 2: Run test to verify it fails**

Run:
`python -m pytest tests/unit/test_mex.py -q`
Expected: FAIL.

**Step 3: Write minimal implementation**

Implement wrapper query minimal + validasi input boundary.

**Step 4: Run test to verify it passes**

Run:
`python -m pytest tests/unit/test_mex.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/client/mex.py waton/client/client.py tests/unit/test_mex.py docs/source/content/client-api-reference.rst
git commit -m "feat(mex): add minimal mex query wrapper"
```

### Task 6: Add practical WAM subset encoder

**Files:**
- Create: `waton/protocol/wam.py`
- Create: `tests/unit/test_wam.py`
- Modify: `docs/source/content/event-model.rst`

**Step 1: Write the failing tests**

Tambah test encoder untuk subset event frame (header + scalar payload types) dan determinism.

**Step 2: Run test to verify it fails**

Run:
`python -m pytest tests/unit/test_wam.py -q`
Expected: FAIL.

**Step 3: Write minimal implementation**

Implement encoder subset (bukan full constants table) untuk event telemetry prioritas.

**Step 4: Run test to verify it passes**

Run:
`python -m pytest tests/unit/test_wam.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/protocol/wam.py tests/unit/test_wam.py docs/source/content/event-model.rst
git commit -m "feat(wam): add practical telemetry encoder subset"
```

### Task 7: Proof layer (parity scan + full verification)

**Files:**
- Modify: `tools/parity/scan_baileys_parity.py`
- Modify: `docs/parity/baileys-parity-baseline.json`
- Modify: `docs/source/content/migration-and-compatibility.rst`
- Modify: `CHANGELOG.md`

**Step 1: Write the failing test/report expectation**

Tambah snapshot/expectation test untuk scanner output domain baru.

**Step 2: Run to verify it fails**

Run scanner + test snapshot.
Expected: FAIL sampai scanner ter-update.

**Step 3: Write minimal implementation**

- Update scanner mapping untuk domain baru (business/usync/mex/wam subset).
- Regenerate baseline parity report.

**Step 4: Run final verification**

Run:
- `python -m pytest tests/unit -q`
- `python -m sphinx -W --keep-going -b html docs/source docs/build/html`
- `python tools/parity/scan_baileys_parity.py --waton waton --baileys "C:/Users/Arvy Kairi/Desktop/whatsapp/Baileys/src" --out docs/parity/baileys-parity-baseline.json`

Expected: PASS + report terbarui.

**Step 5: Commit**

```bash
git add tools/parity/scan_baileys_parity.py docs/parity/baileys-parity-baseline.json docs/source/content/migration-and-compatibility.rst CHANGELOG.md
git commit -m "chore(parity): refresh baileys comparison and verification evidence"
```

### Task 8: Final integration + push branch

**Files:**
- Stage seluruh perubahan branch ini

**Step 1: Verify git state**

Run:
- `git status --short`
- `git log --oneline -n 15`

**Step 2: Final full verification**

Run:
- `python -m pytest tests/unit -q`
- `python -m sphinx -W --keep-going -b html docs/source docs/build/html`

**Step 3: Push**

Run:
`git push -u origin supremacy-hybrid-phase-a`

Expected: branch remote terbuat dan sinkron.
