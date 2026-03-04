# Waton Lint + Type Debt Closure Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Menutup debt lint (Ruff) dan type safety (Pyright strict) agar release gate parity bisa benar-benar end-to-end hijau tanpa skip lint/typecheck.

**Architecture:** Kita pakai pendekatan bertahap berbasis domain risiko: (1) stabilkan test/tooling lint dulu supaya noise turun, (2) bereskan export surface + typing contracts di `waton/app` dan `waton/client`, (3) lanjut ke util/protocol hotspots yang menghasilkan mayoritas `Unknown*` reports. Semua perubahan harus additive/minimal, no refactor besar tanpa kebutuhan test.

**Tech Stack:** Python 3.11+, Ruff, Pyright (strict), pytest.

---

### Task 1: Snapshot baseline diagnostics artifacts

**Files:**
- Create: `.tmp/ruff.json` (generated)
- Create: `.tmp/pyright.json` (generated)
- Create: `docs/parity/artifacts/lint-type-baseline-2026-03-01.md`

**Step 1: Write failing artifact-presence test**

```python
from pathlib import Path


def test_lint_type_baseline_artifacts_exist() -> None:
    assert Path(".tmp/ruff.json").exists()
    assert Path(".tmp/pyright.json").exists()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_lint_type_baseline_artifacts.py::test_lint_type_baseline_artifacts_exist -v`
Expected: FAIL (test file/artifacts belum ada).

**Step 3: Write minimal implementation**

- Tambah `tests/unit/test_lint_type_baseline_artifacts.py`.
- Generate artifacts:
  - `python -m ruff check waton tests tools --output-format json > .tmp/ruff.json || true`
  - `python -m pyright --outputjson > .tmp/pyright.json || true`
- Buat ringkasan angka baseline ke `docs/parity/artifacts/lint-type-baseline-2026-03-01.md`.

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_lint_type_baseline_artifacts.py::test_lint_type_baseline_artifacts_exist -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/unit/test_lint_type_baseline_artifacts.py docs/parity/artifacts/lint-type-baseline-2026-03-01.md
git commit -m "test: snapshot lint and pyright baseline diagnostics"
```

---

### Task 2: Normalize Ruff config for removed rules and test-only ANN policy

**Files:**
- Modify: `ruff.toml`
- Create: `tests/unit/test_ruff_config.py`

**Step 1: Write the failing test**

```python
from pathlib import Path


def test_ruff_config_does_not_ignore_removed_ann_rules() -> None:
    text = Path("ruff.toml").read_text(encoding="utf-8")
    assert "ANN101" not in text
    assert "ANN102" not in text
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ruff_config.py::test_ruff_config_does_not_ignore_removed_ann_rules -v`
Expected: FAIL (config masih ignore ANN101/ANN102).

**Step 3: Write minimal implementation**

- Hapus ignore `ANN101`, `ANN102` dari `ruff.toml`.
- Tambah `per-file-ignores` untuk file test agar debt annotation tests tidak jadi blocker release parity runtime.

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ruff_config.py::test_ruff_config_does_not_ignore_removed_ann_rules -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add ruff.toml tests/unit/test_ruff_config.py
git commit -m "chore: clean ruff config removed ann ignores"
```

---

### Task 3: Fix highest-volume Ruff issues in tests dashboard + golden

**Files:**
- Modify: `tests/unit/test_dashboard.py`
- Modify: `tests/golden/test_codec_golden.py`
- Modify: `tests/integration/test_whatsapp_connection.py`

**Step 1: Write the failing focused lint test command**

Run: `python -m ruff check tests/unit/test_dashboard.py tests/golden/test_codec_golden.py tests/integration/test_whatsapp_connection.py`
Expected: FAIL.

**Step 2: Write minimal implementation**

- Urutkan imports (`I001`).
- Hapus unused import (`F401`).
- Perbaiki trailing whitespace (`W293`).
- Tambah return annotations yang diminta lint untuk fungsi test jika tetap diwajibkan.

**Step 3: Run focused lint command to verify it passes**

Run: `python -m ruff check tests/unit/test_dashboard.py tests/golden/test_codec_golden.py tests/integration/test_whatsapp_connection.py`
Expected: PASS.

**Step 4: Run related tests**

Run:
- `python -m pytest tests/unit/test_dashboard.py -q`
- `python -m pytest tests/golden/test_codec_golden.py -q`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/unit/test_dashboard.py tests/golden/test_codec_golden.py tests/integration/test_whatsapp_connection.py
git commit -m "test: resolve high-volume ruff violations in dashboard and golden suites"
```

---

### Task 4: Fix `waton/__init__.py` export contract for Pyright strict

**Files:**
- Modify: `waton/__init__.py`
- Create: `tests/unit/test_public_exports.py`

**Step 1: Write the failing test**

```python
import waton


def test_public_exports_exist() -> None:
    for name in waton.__all__:
        assert hasattr(waton, name), name
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_public_exports.py::test_public_exports_exist -v`
Expected: FAIL (sejalan dengan `reportUnsupportedDunderAll`).

**Step 3: Write minimal implementation**

- Tambah import/alias eksplisit di `waton/__init__.py` untuk semua item `__all__`.
- Jika ada item yang tidak valid untuk public API, hapus dari `__all__` secara terkontrol.

**Step 4: Verify**

Run:
- `python -m pytest tests/unit/test_public_exports.py::test_public_exports_exist -v`
- `python -m pyright`
Expected: test PASS; jumlah error pyright berkurang signifikan (khusus `reportUnsupportedDunderAll` menjadi 0).

**Step 5: Commit**

```bash
git add waton/__init__.py tests/unit/test_public_exports.py
git commit -m "fix: align waton public exports with strict type checks"
```

---

### Task 5: Reduce `Unknown*` error cluster in `waton/app/*`

**Files:**
- Modify: `waton/app/app.py`
- Modify: `waton/app/context.py`
- Modify: `waton/app/router.py`
- Modify: `waton/app/middleware.py`
- Test: `tests/unit/test_app.py`

**Step 1: Write failing type-focused test command**

Run: `python -m pyright`
Expected: FAIL with errors concentrated in `waton/app/*`.

**Step 2: Write minimal implementation**

- Tambah type alias/protocol callback untuk event handler/middleware.
- Pastikan parameter yang sebelumnya `Unknown` punya annotation konkret.
- Hindari perubahan behavior runtime.

**Step 3: Run verification**

Run:
- `python -m pytest tests/unit/test_app.py -q`
- `python -m pyright`
Expected: app tests PASS, pyright error count turun pada `waton/app/*`.

**Step 4: Commit**

```bash
git add waton/app/app.py waton/app/context.py waton/app/router.py waton/app/middleware.py tests/unit/test_app.py
git commit -m "refactor: add strict typing contracts for app layer callbacks"
```

---

### Task 6: Reduce `Unknown*` error cluster in `waton/client/client.py`

**Files:**
- Modify: `waton/client/client.py`
- Test: `tests/unit/test_client.py`

**Step 1: Write failing type-focused check**

Run: `python -m pyright`
Expected: FAIL with dominant `reportUnknownMemberType/reportUnknownVariableType` in `waton/client/client.py`.

**Step 2: Write minimal implementation**

- Type-kan payload maps (`dict[str, Any]` vs typed dict jika jelas).
- Tambah safe narrowing (`isinstance`, sentinel checks) sebelum `.get()` chained operations.
- Tambah helper typed parser kecil hanya bila dipakai ulang >2 kali (YAGNI/DRY guard).

**Step 3: Verify**

Run:
- `python -m pytest tests/unit/test_client.py -q`
- `python -m pyright`
Expected: client tests PASS; pyright error count turun pada file ini.

**Step 4: Commit**

```bash
git add waton/client/client.py tests/unit/test_client.py
git commit -m "refactor: narrow unknown payload types in client event pipeline"
```

---

### Task 7: Reduce `Unknown*` clusters in `waton/utils` hotspots

**Files:**
- Modify: `waton/utils/crypto.py`
- Modify: `waton/utils/process_message.py`
- Modify: `waton/utils/protocol_message.py`
- Modify: `waton/utils/live_probe.py`
- Tests: `tests/unit/test_messages.py`, `tests/unit/test_messages_recv.py`

**Step 1: Write failing type-focused check**

Run: `python -m pyright`
Expected: FAIL with top errors in listed utils.

**Step 2: Write minimal implementation**

- Tambah annotation return/args + explicit Optional handling.
- Replace ambiguous dict traversals with typed helper extractors.
- Pertahankan behavior decryption/parsing existing.

**Step 3: Verify**

Run:
- `python -m pytest tests/unit/test_messages.py tests/unit/test_messages_recv.py -q`
- `python -m pyright`
Expected: tests PASS; pyright counts down for utils files.

**Step 4: Commit**

```bash
git add waton/utils/crypto.py waton/utils/process_message.py waton/utils/protocol_message.py waton/utils/live_probe.py tests/unit/test_messages.py tests/unit/test_messages_recv.py
git commit -m "refactor: tighten type safety in utility protocol and crypto paths"
```

---

### Task 8: Full gate verification + parity status refresh

**Files:**
- Modify: `docs/plans/2026-03-01-waton-baileys-gap-master-report.md`
- Modify: `CHANGELOG.md`
- Optional Modify: `docs/parity/baileys-parity-latest.json`

**Step 1: Run full verification**

Run:
```bash
python -m pytest tests -q
python -m ruff check waton tests tools
python -m pyright
python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json
python scripts/parity_evidence_smoke.py
```

Expected: all PASS.

**Step 2: Update report and changelog**

- Update master report verification snapshot with latest numbers.
- Update changelog under `Unreleased` for lint/type debt closure scope.

**Step 3: Verify docs (optional but recommended)**

Run: `python -m sphinx -W --keep-going -b html docs/source docs/build/html`
Expected: PASS.

**Step 4: Commit**

```bash
git add CHANGELOG.md docs/plans/2026-03-01-waton-baileys-gap-master-report.md
git commit -m "chore: close lint and typing debt for strict parity release gate"
```

---

## End-of-Plan Verification Commands

1. `python -m pytest tests -q`
2. `python -m ruff check waton tests tools`
3. `python -m pyright`
4. `python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json`
5. `python scripts/parity_evidence_smoke.py`

Expected:
- Semua gate hijau tanpa skip lint/type.
- Strict parity preflight tetap lulus dengan evidence.
- Klaim parity reverse engineering didukung evidence + quality gates lengkap.
