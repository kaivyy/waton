# Waton Baileys Gap Closure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Mengubah parity status Waton dari “done by static scanner” menjadi “proven parity by behavioral evidence” melalui evidence pipeline, replay fixtures, differential checks, dan release gates yang enforceable.

**Architecture:** Pertahankan implementasi domain runtime yang sudah ada (`messages_recv`, `binary_codec`, app-state/retry/group-signal), lalu tambahkan lapisan verifikasi baru di tooling (`tools/parity/*`, `waton/utils/preflight.py`, `scripts/preflight_check.py`) tanpa refactor besar pada core protocol path. Semua perubahan bersifat additive dan berfokus pada confidence, observability, serta governance parity.

**Tech Stack:** Python 3.11+, pytest, dataclasses/json, existing parity scanner, preflight runner, integration live checks, Sphinx docs.

---

### Task 1: Define parity evidence schema and artifact contract

**Files:**
- Create: `docs/parity/evidence-schema.md`
- Create: `docs/parity/artifacts/README.md`
- Test: `tests/unit/test_parity_evidence_schema.py`

**Step 1: Write the failing test**

```python
from tools.parity.evidence import build_empty_evidence


def test_evidence_schema_has_required_fields() -> None:
    evidence = build_empty_evidence(run_id="r1", commit_sha="abc123")
    assert "run_id" in evidence
    assert "domains" in evidence
    assert "timestamp" in evidence
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_parity_evidence_schema.py::test_evidence_schema_has_required_fields -v`
Expected: FAIL (module belum ada).

**Step 3: Write minimal implementation**

```python
# tools/parity/evidence.py
from datetime import datetime, timezone


def build_empty_evidence(run_id: str, commit_sha: str) -> dict:
    return {
        "run_id": run_id,
        "commit_sha": commit_sha,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domains": {},
    }
```

Tambahkan dokumentasi field wajib dan contoh payload di `docs/parity/evidence-schema.md`.

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_parity_evidence_schema.py::test_evidence_schema_has_required_fields -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add docs/parity/evidence-schema.md docs/parity/artifacts/README.md tests/unit/test_parity_evidence_schema.py tools/parity/evidence.py
git commit -m "docs: define parity evidence schema and artifact contract"
```

---

### Task 2: Add fixture index and curation manifest tooling

**Files:**
- Create: `tests/fixtures/parity/README.md`
- Create: `tests/fixtures/parity/index.json`
- Create: `tools/parity/fixture_index.py`
- Test: `tests/unit/test_parity_fixture_index.py`

**Step 1: Write the failing test**

```python
from tools.parity.fixture_index import load_fixture_index


def test_fixture_index_parses_domains() -> None:
    idx = load_fixture_index("tests/fixtures/parity/index.json")
    assert "messages-recv" in idx["domains"]
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_parity_fixture_index.py::test_fixture_index_parses_domains -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
import json
from pathlib import Path


def load_fixture_index(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
```

Buat `index.json` awal dengan domain P0:
- `messages-recv`
- `app-state-sync`
- `retry-manager`
- `group-signal`

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_parity_fixture_index.py::test_fixture_index_parses_domains -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/fixtures/parity/README.md tests/fixtures/parity/index.json tools/parity/fixture_index.py tests/unit/test_parity_fixture_index.py
git commit -m "test: add parity fixture index and loader"
```

---

### Task 3: Implement replay smoke harness with deterministic output snapshots

**Files:**
- Create: `tools/parity/replay_smoke.py`
- Create: `tests/unit/test_parity_replay_smoke.py`
- Create: `tests/fixtures/parity/smoke/*.json`

**Step 1: Write the failing test**

```python
from tools.parity.replay_smoke import replay_fixture


def test_replay_fixture_returns_normalized_event() -> None:
    out = replay_fixture("tests/fixtures/parity/smoke/message-basic.json")
    assert "event_type" in out
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_parity_replay_smoke.py::test_replay_fixture_returns_normalized_event -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
import json
from pathlib import Path


def replay_fixture(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    # smoke-only: pass through expected normalized view
    return data["expected"]
```

Tambahkan fixture smoke awal dengan struktur:
- `input` (captured abstraction)
- `expected` (normalized event)

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_parity_replay_smoke.py::test_replay_fixture_returns_normalized_event -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tools/parity/replay_smoke.py tests/unit/test_parity_replay_smoke.py tests/fixtures/parity/smoke
git commit -m "test: add parity replay smoke harness"
```

---

### Task 4: Upgrade parity scanner from static-only to static+evidence mode

**Files:**
- Modify: `tools/parity/scan_baileys_parity.py`
- Create: `tests/unit/test_parity_scan_evidence_mode.py`
- Modify: `docs/parity/baileys-parity-latest.json` (format extension as needed)

**Step 1: Write the failing test**

```python
from tools.parity.scan_baileys_parity import scan_parity


def test_scan_parity_accepts_evidence_overlay(tmp_path) -> None:
    evidence = {"domains": {"messages-recv": {"replay_pass_rate": 1.0, "unknown_event_count": 0}}}
    report = scan_parity("waton", "C:/Users/Arvy Kairi/Desktop/whatsapp/Baileys/src", evidence=evidence)
    assert "domains" in report
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_parity_scan_evidence_mode.py::test_scan_parity_accepts_evidence_overlay -v`
Expected: FAIL (signature belum support evidence).

**Step 3: Write minimal implementation**

- Tambahkan arg opsional `evidence: dict | None = None` di `scan_parity`.
- Merge metadata evidence ke report domain tanpa mengubah backward-compat output utama.
- Tambah CLI arg opsional `--evidence`.

Contoh minimal:

```python
def scan_parity(..., evidence: dict | None = None) -> dict:
    report = {"domains": domains}
    if evidence and isinstance(evidence.get("domains"), dict):
        for name, payload in report["domains"].items():
            payload["evidence"] = evidence["domains"].get(name, {})
    return report
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_parity_scan_evidence_mode.py::test_scan_parity_accepts_evidence_overlay -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tools/parity/scan_baileys_parity.py tests/unit/test_parity_scan_evidence_mode.py
git commit -m "feat: add evidence-aware parity scan mode"
```

---

### Task 5: Enforce parity evidence validation in preflight (strict mode)

**Files:**
- Modify: `waton/utils/preflight.py`
- Modify: `scripts/preflight_check.py`
- Create: `tests/unit/test_preflight_parity_strict.py`

**Step 1: Write the failing test**

```python
from waton.utils.preflight import validate_parity_report


def test_validate_parity_report_fails_when_done_without_evidence() -> None:
    report = {"domains": {"messages-recv": {"status": "done"}}}
    issues = validate_parity_report(report)
    assert issues
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_preflight_parity_strict.py::test_validate_parity_report_fails_when_done_without_evidence -v`
Expected: FAIL (validator saat ini meloloskan done tanpa evidence).

**Step 3: Write minimal implementation**

- Tambah mode strict config (mis. env/flag `--parity-strict`).
- Saat strict, domain `done` wajib punya field evidence minimal:
  - `replay_pass_rate`
  - `unknown_event_count`
  - `drift_count`

Contoh rule minimal:

```python
if strict and status == "done":
    ev = payload.get("evidence", {})
    required = ["replay_pass_rate", "unknown_event_count", "drift_count"]
    missing = [k for k in required if k not in ev]
    if missing:
        issues.append(f"{domain}: missing evidence {missing}")
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_preflight_parity_strict.py::test_validate_parity_report_fails_when_done_without_evidence -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add waton/utils/preflight.py scripts/preflight_check.py tests/unit/test_preflight_parity_strict.py
git commit -m "feat: add strict parity evidence validation in preflight"
```

---

### Task 6: Add unknown-event telemetry summarizer for receive pipeline outputs

**Files:**
- Create: `tools/parity/unknown_telemetry.py`
- Create: `tests/unit/test_unknown_telemetry.py`
- Create: `docs/parity/artifacts/unknown-telemetry-sample.json`

**Step 1: Write the failing test**

```python
from tools.parity.unknown_telemetry import summarize_unknown_events


def test_summarize_unknown_events_counts_types() -> None:
    rows = [{"event_type": "unknown_x"}, {"event_type": "unknown_x"}, {"event_type": "unknown_y"}]
    out = summarize_unknown_events(rows)
    assert out["unknown_x"] == 2
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_unknown_telemetry.py::test_summarize_unknown_events_counts_types -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
def summarize_unknown_events(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        et = row.get("event_type")
        if isinstance(et, str) and et.startswith("unknown"):
            counts[et] = counts.get(et, 0) + 1
    return counts
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_unknown_telemetry.py::test_summarize_unknown_events_counts_types -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add tools/parity/unknown_telemetry.py tests/unit/test_unknown_telemetry.py docs/parity/artifacts/unknown-telemetry-sample.json
git commit -m "test: add unknown-event telemetry summarizer"
```

---

### Task 7: Introduce parity release evidence runbook and governance table

**Files:**
- Modify: `docs/runbooks/parity-release-checklist.md`
- Create: `docs/runbooks/parity-domain-ownership.md`
- Modify: `CHANGELOG.md`

**Step 1: Write failing docs gate command**

Run: `python -m sphinx -W --keep-going -b html docs/source docs/build/html`
Expected: FAIL jika referensi docs baru belum sinkron.

**Step 2: Write minimal docs implementation**

- Tambahkan section di checklist:
  - required evidence bundle
  - strict mode release gate
  - threshold minimum
- Tambahkan domain ownership + backup owner + SLA matrix di runbook baru.
- Tambahkan changelog under Unreleased.

**Step 3: Run docs gate and targeted tests**

Run:
- `python -m pytest tests/unit/test_preflight_parity_strict.py -q`
- `python -m pytest tests/unit/test_parity_scan_evidence_mode.py -q`
- `python -m sphinx -W --keep-going -b html docs/source docs/build/html`

Expected: PASS.

**Step 4: Commit**

```bash
git add docs/runbooks/parity-release-checklist.md docs/runbooks/parity-domain-ownership.md CHANGELOG.md
git commit -m "docs: add parity evidence governance and ownership model"
```

---

### Task 8: Add aggregate command for parity evidence smoke pipeline

**Files:**
- Create: `scripts/parity_evidence_smoke.py`
- Create: `tests/unit/test_parity_evidence_smoke_script.py`
- Modify: `README.md`

**Step 1: Write the failing test**

```python
from scripts.parity_evidence_smoke import build_commands


def test_build_commands_contains_scan_and_replay() -> None:
    cmds = build_commands()
    names = [c["name"] for c in cmds]
    assert "parity-scan" in names
    assert "parity-replay-smoke" in names
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_parity_evidence_smoke_script.py::test_build_commands_contains_scan_and_replay -v`
Expected: FAIL.

**Step 3: Write minimal implementation**

```python
def build_commands() -> list[dict[str, str]]:
    return [
        {"name": "parity-scan", "cmd": "python -m tools.parity.scan_baileys_parity ..."},
        {"name": "parity-replay-smoke", "cmd": "python -m tools.parity.replay_smoke ..."},
    ]
```

Tambahkan README section: “Parity Evidence Smoke”.

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_parity_evidence_smoke_script.py::test_build_commands_contains_scan_and_replay -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add scripts/parity_evidence_smoke.py tests/unit/test_parity_evidence_smoke_script.py README.md
git commit -m "chore: add parity evidence smoke script and usage docs"
```

---

### Task 9: Final integration verification and baseline refresh flow

**Files:**
- Modify: `docs/parity/baileys-parity-latest.json` (generated)
- Optional modify: `docs/parity/baileys-parity-baseline.json` (if update approved)
- Modify: `docs/plans/2026-03-01-waton-baileys-gap-master-report.md` (status notes)

**Step 1: Run full verification**

Run:
```bash
python -m pytest tests -q
python -m ruff check waton tests tools
python -m pyright
python scripts/preflight_check.py --skip-lint --skip-typecheck
python scripts/parity_evidence_smoke.py
```

Expected: PASS.

**Step 2: Verify strict mode readiness**

Run:
```bash
python scripts/preflight_check.py --parity-strict --skip-lint --skip-typecheck
```

Expected: PASS (or actionable list of missing evidence fields).

**Step 3: Sync docs and baseline policy**

- Update master report status section with implemented tooling upgrades.
- If approved by maintainer, copy latest to baseline.

**Step 4: Commit**

```bash
git add docs/parity/baileys-parity-latest.json docs/parity/baileys-parity-baseline.json docs/plans/2026-03-01-waton-baileys-gap-master-report.md
 git commit -m "docs: refresh parity evidence baseline and implementation status"
```

---

## End-of-Plan Verification Commands

1. `python -m pytest tests -q`
2. `python -m ruff check waton tests tools`
3. `python -m pyright`
4. `python scripts/preflight_check.py --parity-strict`
5. `python scripts/parity_evidence_smoke.py`

Expected:
- Scanner tetap menghasilkan domain map lengkap.
- Strict preflight menolak domain `done` tanpa evidence.
- Replay smoke + telemetry artifacts dihasilkan.
- Runbook parity memiliki ownership + governance yang operasional.

## Notes

- Plan ini sengaja **tidak** memaksa refactor besar runtime protocol; fokus pada hardening confidence agar gap terhadap Baileys tertutup dari sisi reverse evidence dan release discipline.
- Implementasi bertahap (additive) menjaga risiko regressions tetap rendah sambil menaikkan kualitas parity claim.
