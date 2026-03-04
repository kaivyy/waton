# Waton Baileys 100% Parity Design Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Menetapkan dan mengimplementasikan hard-block PR gate agar Waton hanya bisa merge jika lolos parity hybrid ketat terhadap Baileys main (wire parity + behavior parity + strict evidence parity).

**Architecture:** Desain ini menambahkan differential parity harness lintas runtime (Node oracle Baileys vs Python Waton), canonicalization layer untuk field nondeterministic, dan PR gate policy yang memblok merge saat terjadi wire/behavior drift atau strict evidence threshold failure. Bukti parity disimpan sebagai artifact terstruktur, diverifikasi oleh preflight strict, lalu dipakai sebagai sumber kebenaran operasional untuk release dan triage incident.

**Tech Stack:** Python (`scripts/preflight_check.py`, `waton/utils/preflight.py`, `tools/parity/*`), pytest, JSON artifacts, Baileys main (Node runtime oracle), CI status checks, runbook governance (`docs/runbooks/*`).

---

## Context
Project ini adalah konversi Node TypeScript (Baileys) ke Python (Waton). Target baru adalah **100% parity operasional**, bukan sekadar scanner static status `done`. Saat ini fondasi parity sudah kuat (strict preflight lulus), tetapi gap utama adalah belum adanya enforced differential parity lintas runtime di PR gate harian.

Keputusan desain yang disetujui:
1. Definisi parity = **Hybrid ketat** (wire + behavior + strict evidence).
2. Baseline referensi = **Baileys main branch**.
3. Gate policy = **Hard-block PR**.

---

## Task 1: Kunci Definisi Gate “100% Parity” ke Dokumen Operasional

**Files:**
- Modify: `docs/runbooks/parity-release-checklist.md`
- Modify: `docs/runbooks/parity-domain-ownership.md`
- Modify: `docs/parity/evidence-schema.md`
- Test: `tests/unit/test_preflight.py`

**Step 1: Write failing test/validation expectation**
- Tambahkan assertion-level test untuk memastikan strict gate bukan hanya cek key evidence, tapi juga threshold policy (sudah mulai tersedia; finalisasi jika perlu domain-specific policy extension).

**Step 2: Run test to verify failure (if policy belum terefleksi penuh)**
Run:
```bash
python -m pytest tests/unit/test_preflight.py -q
```
Expected:
- FAIL jika threshold policy belum tercakup lengkap sesuai dokumen.

**Step 3: Implement minimal documentation alignment**
- Tegaskan di runbook bahwa claim “100% parity” mensyaratkan tiga lapis gate (wire/behavior/evidence).
- Tegaskan domain ownership + escalation untuk PR hard-block incident.
- Tegaskan schema evidence menyertakan pointer artifact differential run.

**Step 4: Run tests/docs checks**
Run:
```bash
python -m pytest tests/unit/test_preflight.py -q
```
Expected:
- PASS.

**Step 5: Commit**
```bash
git add docs/runbooks/parity-release-checklist.md docs/runbooks/parity-domain-ownership.md docs/parity/evidence-schema.md tests/unit/test_preflight.py
git commit -m "docs: define 100% parity as hybrid strict gate"
```

---

## Task 2: Bangun Differential Harness Contract (Oracle Baileys main vs Waton)

**Files:**
- Create: `tools/parity/differential_harness.py`
- Create: `tools/parity/canonicalize.py`
- Create: `tools/parity/oracle_runner.py`
- Create: `tests/unit/test_parity_differential_harness.py`
- Modify: `docs/parity/artifacts/README.md`

**Step 1: Write failing tests for contract**
Tambahkan test yang memverifikasi:
- input scenario menghasilkan dua stream (oracle + waton),
- canonicalization menormalkan field nondeterministic,
- comparator menghasilkan hasil deterministik (`wire_pass`, `behavior_pass`, `drift_summary`).

**Step 2: Run test to verify failure**
Run:
```bash
python -m pytest tests/unit/test_parity_differential_harness.py -q
```
Expected:
- FAIL karena harness belum diimplementasikan.

**Step 3: Implement minimal harness**
- `oracle_runner.py`: jalankan runner Baileys main dan capture artifact oracle (via command boundary, tanpa embed logic Baileys ke Python).
- `canonicalize.py`: normalisasi timestamp, nonce, generated ids, host metadata.
- `differential_harness.py`: bandingkan oracle vs waton per `scenario_id/phase/order_index`.

**Step 4: Run test to verify pass**
Run:
```bash
python -m pytest tests/unit/test_parity_differential_harness.py -q
```
Expected:
- PASS.

**Step 5: Commit**
```bash
git add tools/parity/differential_harness.py tools/parity/canonicalize.py tools/parity/oracle_runner.py tests/unit/test_parity_differential_harness.py docs/parity/artifacts/README.md
git commit -m "feat: add parity differential harness contract"
```

---

## Task 3: Integrasi Harness ke Preflight Strict & Evidence Bundle

**Files:**
- Modify: `scripts/preflight_check.py`
- Modify: `waton/utils/preflight.py`
- Modify: `tools/parity/scan_baileys_parity.py`
- Modify: `scripts/parity_evidence_smoke.py`
- Create/Modify: `tests/unit/test_preflight_parity_strict.py`
- Create: `tests/unit/test_parity_evidence_pipeline.py`

**Step 1: Write failing integration tests**
- Test bahwa mode strict gagal jika differential artifact menunjukkan wire/behavior drift.
- Test bahwa mode strict lulus jika wire+behavior pass dan threshold evidence pass.

**Step 2: Run tests to verify failure**
Run:
```bash
python -m pytest tests/unit/test_preflight_parity_strict.py tests/unit/test_parity_evidence_pipeline.py -q
```
Expected:
- FAIL sebelum integrasi selesai.

**Step 3: Implement minimal integration**
- Tambahkan command stage differential parity dalam preflight strict mode.
- Simpan artifact run di path standar `docs/parity/artifacts/<run-id>/...`.
- Attach ringkasan differential result ke parity report/evidence payload.

**Step 4: Run tests to verify pass**
Run:
```bash
python -m pytest tests/unit/test_preflight_parity_strict.py tests/unit/test_parity_evidence_pipeline.py -q
```
Expected:
- PASS.

**Step 5: Commit**
```bash
git add scripts/preflight_check.py waton/utils/preflight.py tools/parity/scan_baileys_parity.py scripts/parity_evidence_smoke.py tests/unit/test_preflight_parity_strict.py tests/unit/test_parity_evidence_pipeline.py
git commit -m "feat: enforce differential parity in strict preflight"
```

---

## Task 4: Terapkan Hard-Block PR Policy dan Incident Flow

**Files:**
- Create/Modify: `.github/workflows/parity-gate.yml` (atau workflow CI setara di repo)
- Modify: `docs/runbooks/parity-domain-ownership.md`
- Modify: `docs/runbooks/parity-release-checklist.md`
- Create: `docs/runbooks/parity-pr-incident-flow.md`
- Test: `tests/unit/test_parity_evidence_smoke_script.py`

**Step 1: Write failing policy test/check**
- Tambahkan validasi script/workflow supaya check names wajib muncul (`parity-oracle-main-sync`, `parity-diff-wire`, `parity-diff-behavior`, `parity-strict-evidence`).

**Step 2: Run test/check to verify failure**
Run:
```bash
python -m pytest tests/unit/test_parity_evidence_smoke_script.py -q
```
Expected:
- FAIL jika policy stage belum lengkap.

**Step 3: Implement minimal CI policy**
- Snapshot `baileys_main_sha` per run.
- Jalankan differential harness + strict preflight.
- Publish artifact bundle.
- Set branch protection: semua parity checks wajib hijau.

**Step 4: Run verification**
Run:
```bash
python -m pytest tests/unit/test_parity_evidence_smoke_script.py -q
python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json --skip-lint --skip-typecheck
```
Expected:
- PASS.

**Step 5: Commit**
```bash
git add .github/workflows/parity-gate.yml docs/runbooks/parity-domain-ownership.md docs/runbooks/parity-release-checklist.md docs/runbooks/parity-pr-incident-flow.md tests/unit/test_parity_evidence_smoke_script.py
git commit -m "ci: hard-block PR on parity hybrid gate"
```

---

## Task 5: Final Verification + Changelog + Developer UX

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/plans/2026-03-01-waton-baileys-gap-master-report.md`

**Step 1: Write/update verification checklist test references**
- Pastikan command final tercantum dan konsisten dengan CI policy.

**Step 2: Run full verification**
Run:
```bash
python -m pytest tests -q
python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json --skip-lint --skip-typecheck
python scripts/parity_evidence_smoke.py
```
Expected:
- Semua gate parity strict lulus.

**Step 3: Update docs + changelog**
- README: satu jalur jelas untuk parity hard-block PR mode.
- CHANGELOG: ringkas perubahan gate, harness, policy.
- Master report: tandai milestone parity hybrid enforced.

**Step 4: Commit**
```bash
git add README.md CHANGELOG.md docs/plans/2026-03-01-waton-baileys-gap-master-report.md
git commit -m "docs: publish 100% parity hard-block workflow"
```

---

## Verification Matrix (End-to-End)

1. **Unit integrity**
```bash
python -m pytest tests/unit/test_preflight.py tests/unit/test_preflight_parity_strict.py tests/unit/test_parity_evidence_pipeline.py tests/unit/test_parity_differential_harness.py -q
```

2. **Strict parity gate**
```bash
python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json --skip-lint --skip-typecheck
```

3. **Parity smoke**
```bash
python scripts/parity_evidence_smoke.py
```

4. **Artifact checks**
- `docs/parity/baileys-parity-latest.json` terisi evidence yang konsisten.
- `docs/parity/baileys-parity-baseline.json` sinkron saat mode baseline update dijalankan.
- Artifact differential per run tersedia untuk audit dan triage.

5. **PR policy checks**
- Status checks wajib hijau untuk merge:
  - `parity-oracle-main-sync`
  - `parity-diff-wire`
  - `parity-diff-behavior`
  - `parity-strict-evidence`

---

## Critical Reuse References

- Existing strict validator: `waton/utils/preflight.py`
- Existing preflight runner: `scripts/preflight_check.py`
- Existing parity scan/evidence overlay: `tools/parity/scan_baileys_parity.py`
- Existing smoke runner: `scripts/parity_evidence_smoke.py`
- Existing governance docs: `docs/runbooks/parity-release-checklist.md`, `docs/runbooks/parity-domain-ownership.md`

Plan ini menjaga prinsip DRY/YAGNI: pakai pipeline yang sudah ada sebagai fondasi, lalu tambahkan differential parity layer dan hard-block policy tanpa rewrite besar.