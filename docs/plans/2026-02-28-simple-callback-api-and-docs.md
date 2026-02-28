# Simple Callback API + RTD Docs Update Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Menyediakan API drop-in paling sederhana (`from waton import simple`) agar user bisa langsung import, register handler pesan, dan run dengan boilerplate minimum.

**Architecture:** Tambahkan lapisan wrapper tipis di atas `App` tanpa mengubah pipeline core (`WAClient`, decrypt, router). Wrapper ini memetakan `Context` menjadi objek pesan sederhana yang ergonomis (`text`, `from_jid`, `reply`). Surface package (`waton.__init__`) diekspose secara lazy agar startup/import tetap ringan.

**Tech Stack:** Python 3.11, pytest, Sphinx (Read the Docs), existing Waton App/Client stack.

---

### Task 1: Tambahkan regression test untuk API sederhana (TDD RED)

**Files:**
- Create: `tests/unit/test_simple_api.py`
- Test: `tests/unit/test_app.py` (reference behavior)

**Step 1: Write the failing test**

```python
def test_waton_exports_simple_factory():
    import waton
    assert callable(waton.simple)
```

```python
async def test_simple_client_on_message_wraps_context_and_reply(monkeypatch):
    ...
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_simple_api.py -q`
Expected: FAIL karena `waton.simple` belum tersedia / wrapper belum ada.

**Step 3: Write minimal implementation**

Implement modul API sederhana + lazy export pada package root.

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_simple_api.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/unit/test_simple_api.py waton/simple_api.py waton/__init__.py
git commit -m "feat: add simple callback API surface"
```

### Task 2: Implement API wrapper minimal dan jaga performa import

**Files:**
- Create: `waton/simple_api.py`
- Modify: `waton/__init__.py`

**Step 1: Write the failing test**

```python
async def test_simple_client_on_ready_passes_simple_client():
    ...
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_simple_api.py -q`
Expected: FAIL on callback bridge behavior.

**Step 3: Write minimal implementation**

- `simple(storage_path="waton.db") -> SimpleClient`
- `SimpleClient.on_message` decorator gaya callback
- `SimpleIncomingMessage` helper (`text`, `from_jid`, `sender`, `reply`, `react`)
- `SimpleClient.run()` delegasi ke `App.run()`
- `waton.__getattr__` lazy export untuk `simple`, `SimpleClient`, `SimpleIncomingMessage`

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_simple_api.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/simple_api.py waton/__init__.py tests/unit/test_simple_api.py
git commit -m "feat: expose simple callback client"
```

### Task 3: Update README + Read the Docs for perubahan API

**Files:**
- Modify: `README.md`
- Modify: `docs/source/content/getting-started.rst`
- Modify: `docs/source/content/quickstart-app.rst`
- Modify: `docs/source/content/migration-and-compatibility.rst`
- Modify: `CHANGELOG.md`

**Step 1: Write the failing docs check (strict build)**

Run: `python -m sphinx -W --keep-going -b html docs/source docs/build/html`
Expected: Bisa gagal jika ada referensi docs belum sinkron.

**Step 2: Write minimal docs implementation**

- Tambahkan section quick usage `from waton import simple`
- Jelaskan posisi `simple` vs `App`
- Tambahkan migration note bahwa API baru bersifat additive (backward-compatible)
- Catat perubahan di changelog

**Step 3: Run docs check and tests**

Run:
- `python -m pytest tests/unit/test_simple_api.py -q`
- `python -m pytest tests/unit -q`
- `python -m sphinx -W --keep-going -b html docs/source docs/build/html`

Expected: PASS.

**Step 4: Commit**

```bash
git add README.md docs/source/content/getting-started.rst docs/source/content/quickstart-app.rst docs/source/content/migration-and-compatibility.rst CHANGELOG.md
git commit -m "docs: add simple API usage and migration notes"
```

### Task 4: Final integration commit + push branch

**Files:**
- Modify/stage all relevant source, tests, docs

**Step 1: Verify working tree + diff + log style**

Run:
- `git status --short`
- `git diff --staged`
- `git diff`
- `git log --oneline -n 10`

**Step 2: Final test proof before release action**

Run:
- `python -m pytest tests/unit -q`
- `python -m sphinx -W --keep-going -b html docs/source docs/build/html`

**Step 3: Commit all intended changes**

```bash
git add <intended-files>
git commit -m "feat: add simple callback API and docs update"
```

**Step 4: Push**

```bash
git push
```

Expected: remote update sukses.
