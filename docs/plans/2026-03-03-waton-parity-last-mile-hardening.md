# Waton Parity Last-Mile Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Menutup gap operasional terakhir agar klaim parity Waton vs Baileys didukung evidence CI yang fresh, enforceable, dan anti-regression.

**Architecture:** Kita tidak rewrite pipeline parity yang sudah hijau. Kita tambahkan guardrails di boundary CI/preflight: evidence harus fresh (run metadata valid + commit SHA match), artefak differential harus dipublish dan tervalidasi, dan PR gate harus benar-benar hard-block dengan check names yang konsisten. Pendekatan ini DRY/YAGNI: memanfaatkan `preflight_check.py`, `waton/utils/preflight.py`, `scripts/parity_evidence_smoke.py`, dan workflow parity yang sudah ada.

**Tech Stack:** Python 3.11+, pytest, GitHub Actions workflow, JSON evidence artifacts, preflight/parity tooling (`scripts/*`, `waton/utils/preflight.py`, `tools/parity/*`).

---

### Task 1: Enforce fresh evidence metadata in strict preflight

**Files:**
- Modify: `waton/utils/preflight.py`
- Modify: `scripts/preflight_check.py`
- Test: `tests/unit/test_preflight_parity_strict.py`

**Step 1: Write the failing test**

Tambahkan test yang memastikan strict mode gagal jika metadata evidence top-level tidak valid.

```python
def test_validate_parity_report_strict_requires_top_level_evidence_metadata() -> None:
    report = {
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": 1.0,
                    "unknown_event_count": 0,
                    "drift_count": 0,
                    "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
                    "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
                },
            }
        }
    }
    issues = validate_parity_report(report, strict=True)
    assert any("run_id" in issue for issue in issues)
    assert any("commit_sha" in issue for issue in issues)
    assert any("timestamp" in issue for issue in issues)
```

Tambahkan test untuk SHA mismatch (strict + expected SHA):

```python
def test_validate_parity_report_strict_rejects_commit_sha_mismatch() -> None:
    report = {
        "run_id": "r1",
        "commit_sha": "abc123",
        "timestamp": "2026-03-03T00:00:00+00:00",
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": 1.0,
                    "unknown_event_count": 0,
                    "drift_count": 0,
                    "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
                    "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
                },
            }
        },
    }
    issues = validate_parity_report(report, strict=True, expected_commit_sha="def456")
    assert any("commit_sha mismatch" in issue for issue in issues)
```

**Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/unit/test_preflight_parity_strict.py -q
```
Expected:
- FAIL (karena validator belum enforce metadata top-level / expected commit SHA).

**Step 3: Write minimal implementation**

1. Update signature validator:
```python
def validate_parity_report(report: dict[str, Any], *, strict: bool = False, expected_commit_sha: str | None = None) -> list[str]:
```

2. Saat `strict=True`, enforce:
- `run_id` harus string non-empty.
- `commit_sha` harus string non-empty.
- `timestamp` harus string non-empty.
- Jika `expected_commit_sha` diberikan dan tidak cocok dengan `report["commit_sha"]` -> issue `commit_sha mismatch`.

3. Di `scripts/preflight_check.py`, tambahkan arg parser:
- `--expected-commit-sha` (default `None`)

Lalu pass ke validator:
```python
issues = validate_parity_report(
    report,
    strict=args.parity_strict,
    expected_commit_sha=args.expected_commit_sha,
)
```

**Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest tests/unit/test_preflight_parity_strict.py -q
```
Expected:
- PASS.

**Step 5: Commit**

```bash
git add waton/utils/preflight.py scripts/preflight_check.py tests/unit/test_preflight_parity_strict.py
git commit -m "feat: enforce strict evidence metadata and commit sha matching"
```

---

### Task 2: Enforce strict evidence stage contract in smoke pipeline

**Files:**
- Modify: `scripts/parity_evidence_smoke.py`
- Test: `tests/unit/test_parity_evidence_smoke_script.py`

**Step 1: Write the failing test**

Tambahkan test agar strict evidence stage meneruskan expected SHA ke preflight.

```python
def test_build_commands_strict_stage_includes_expected_commit_sha() -> None:
    evidence_path = "docs/parity/artifacts/strict-evidence-sample.json"
    cmds = build_commands(
        baileys_src="C:/Baileys/src",
        evidence_path=evidence_path,
        expected_commit_sha="deadbeef",
    )
    strict_cmd = next(c for c in cmds if c["name"] == "parity-strict-evidence")
    assert "--expected-commit-sha" in strict_cmd["args"]
    assert "deadbeef" in strict_cmd["args"]
```

**Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/unit/test_parity_evidence_smoke_script.py -q
```
Expected:
- FAIL (karena `build_commands` belum support `expected_commit_sha`).

**Step 3: Write minimal implementation**

1. Update function signature:
```python
def build_commands(*, baileys_src: str, evidence_path: str | None = None, expected_commit_sha: str | None = None) -> list[dict[str, object]]:
```

2. Saat strict stage ditambahkan (`parity-strict-evidence`), append:
- `--expected-commit-sha <sha>` jika `expected_commit_sha` diisi.

3. Tambahkan CLI arg pada parser:
- `--expected-commit-sha`

4. Forward arg ke `build_commands(...)` di `main()`.

**Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest tests/unit/test_parity_evidence_smoke_script.py -q
```
Expected:
- PASS.

**Step 5: Commit**

```bash
git add scripts/parity_evidence_smoke.py tests/unit/test_parity_evidence_smoke_script.py
git commit -m "feat: thread expected commit sha through parity evidence smoke"
```

---

### Task 3: Tighten evidence-overlay contract for parity scan inputs

**Files:**
- Modify: `tools/parity/scan_baileys_parity.py`
- Test: `tests/unit/test_parity_scan_evidence_mode.py`

**Step 1: Write the failing test**

Tambahkan test untuk memastikan evidence overlay memvalidasi top-level metadata minimal saat diberikan.

```python
def test_scan_parity_rejects_evidence_without_required_top_level_fields(tmp_path: Path) -> None:
    # setup minimal waton/baileys files seperti test existing
    evidence = {"domains": {"messages-recv": {"replay_pass_rate": 1.0}}}

    with pytest.raises(ValueError, match="missing required evidence top-level fields"):
        scan_parity(str(waton_root), str(baileys_src), evidence=evidence)
```

**Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/unit/test_parity_scan_evidence_mode.py -q
```
Expected:
- FAIL (belum ada validasi top-level evidence).

**Step 3: Write minimal implementation**

Di `scan_parity(...)` sebelum overlay evidence:
- Jika `evidence is not None`, validate top-level keys: `run_id`, `commit_sha`, `timestamp`, `domains`.
- Jika ada yang hilang -> `raise ValueError("missing required evidence top-level fields: ...")`.

Pertahankan behavior overlay domain existing agar backward-compatible untuk structure `domains`.

**Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest tests/unit/test_parity_scan_evidence_mode.py -q
```
Expected:
- PASS.

**Step 5: Commit**

```bash
git add tools/parity/scan_baileys_parity.py tests/unit/test_parity_scan_evidence_mode.py
git commit -m "fix: validate evidence top-level metadata for parity scan overlay"
```

---

### Task 4: Upgrade parity gate workflow to CI-fresh evidence + artifact publishing

**Files:**
- Modify: `.github/workflows/parity-gate.yml`
- Test: `tests/unit/test_parity_evidence_smoke_script.py`
- Modify: `docs/parity/artifacts/README.md`

**Step 1: Write the failing test**

Tambahkan test checklist-style yang memastikan dokumentasi artifacts menyebut “CI-generated evidence required for release/PR strict mode”.

```python
def test_artifacts_readme_mentions_ci_generated_evidence_requirement() -> None:
    text = Path("docs/parity/artifacts/README.md").read_text(encoding="utf-8")
    assert "CI-generated evidence" in text
    assert "sample evidence is for local/dev only" in text
```

**Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/unit/test_parity_evidence_smoke_script.py -q
```
Expected:
- FAIL jika requirement text belum ada.

**Step 3: Write minimal implementation**

1. Update workflow `.github/workflows/parity-gate.yml`:
- Generate run id (contoh `${{ github.run_id }}-${{ github.run_attempt }}`).
- Export `EXPECTED_SHA=${{ github.sha }}`.
- Jalankan strict preflight dengan:
  - `--parity-evidence <generated-path>`
  - `--expected-commit-sha $EXPECTED_SHA`
- Upload artifact bundle (wire, behavior, evidence json) via `actions/upload-artifact`.

2. Update `docs/parity/artifacts/README.md` menegaskan:
- CI strict/release mode wajib pakai CI-generated evidence.
- sample evidence hanya local/dev smoke.

**Step 4: Run tests to verify it passes**

Run:
```bash
python -m pytest tests/unit/test_parity_evidence_smoke_script.py -q
```
Expected:
- PASS.

**Step 5: Commit**

```bash
git add .github/workflows/parity-gate.yml docs/parity/artifacts/README.md tests/unit/test_parity_evidence_smoke_script.py
git commit -m "ci: publish parity artifacts and enforce ci-generated strict evidence"
```

---

### Task 5: Sync docs and changelog with the new strict evidence policy

**Files:**
- Modify: `docs/parity/evidence-schema.md`
- Modify: `docs/runbooks/parity-release-checklist.md`
- Modify: `docs/runbooks/parity-domain-ownership.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Step 1: Write the failing docs assertion test**

Tambahkan test ringan untuk memastikan runbook mencantumkan expected-commit enforcement.

```python
def test_release_checklist_mentions_expected_commit_sha_enforcement() -> None:
    text = Path("docs/runbooks/parity-release-checklist.md").read_text(encoding="utf-8")
    assert "expected commit sha" in text.lower()
```

**Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/unit/test_preflight.py -q
```
Expected:
- FAIL bila assertion baru belum terpenuhi.

**Step 3: Write minimal documentation implementation**

1. `docs/parity/evidence-schema.md`:
- Nyatakan `run_id`, `commit_sha`, `timestamp` wajib untuk strict/release gate.

2. `docs/runbooks/parity-release-checklist.md`:
- Tambahkan langkah strict command dengan `--expected-commit-sha <sha>` di CI.

3. `docs/runbooks/parity-domain-ownership.md`:
- Tambahkan policy note: incident jika strict evidence commit mismatch.

4. `README.md`:
- Tambahkan contoh command strict parity dengan expected sha untuk CI context.

5. `CHANGELOG.md`:
- Catat policy upgrade: strict parity sekarang enforce fresh evidence metadata + commit sha match.

**Step 4: Run tests to verify pass**

Run:
```bash
python -m pytest tests/unit/test_preflight.py -q
python -m pytest tests/unit/test_preflight_parity_strict.py tests/unit/test_parity_scan_evidence_mode.py tests/unit/test_parity_evidence_smoke_script.py tests/unit/test_parity_evidence_pipeline.py -q
```
Expected:
- PASS.

**Step 5: Commit**

```bash
git add docs/parity/evidence-schema.md docs/runbooks/parity-release-checklist.md docs/runbooks/parity-domain-ownership.md README.md CHANGELOG.md tests/unit/test_preflight.py
git commit -m "docs: require fresh strict parity evidence and commit-sha enforcement"
```

---

## End-of-Plan Verification Commands

1. Unit + strict parity validation surface:
```bash
python -m pytest tests/unit/test_preflight.py tests/unit/test_preflight_parity_strict.py tests/unit/test_parity_scan_evidence_mode.py tests/unit/test_parity_evidence_smoke_script.py tests/unit/test_parity_evidence_pipeline.py -q
```

2. Full non-skip repo gate:
```bash
python -m pytest tests -q
python -m ruff check waton tests tools
python -m pyright
```

3. Strict preflight (local sample smoke):
```bash
python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json
```

4. Parity smoke with expected sha wiring check:
```bash
python scripts/parity_evidence_smoke.py --parity-evidence docs/parity/artifacts/strict-evidence-sample.json --expected-commit-sha local-working-tree
```

Expected final state:
- Semua test baru/lama terkait parity strict evidence PASS.
- Strict validator enforce top-level metadata + optional commit SHA match.
- CI workflow parity gate publish artifacts dan enforce fresh evidence policy.
- Docs/runbook/README/changelog sinkron dengan policy baru.
