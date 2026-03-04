# Waton vs Baileys Gap Master Report (12-Month) + Technical Appendices

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Mendefinisikan gap real Waton agar mencapai parity-level Baileys secara *behavioral reliability* (bukan sekadar line-count parity), terutama pada reverse engineering depth, protocol fidelity, tooling maturity, dan release safety.

**Architecture:** Dokumen ini memakai model “core parity done but verification depth insufficient”. Kita treat status `done` saat ini sebagai *foundation milestone*, lalu menambahkan lapisan validasi yang lebih keras: byte-level fixtures, cross-runtime differential tests, unknown-field telemetry, replay/chaos harness, dan release gates berlapis.

**Tech Stack:** Python 3.11+, Rust (PyO3 crypto), pytest, Sphinx, parity scanner (`tools/parity/scan_baileys_parity.py`), preflight runner (`scripts/preflight_check.py`), protobuf schema/bindings (`WAProto.proto`, `WAProto_pb2.py`).

---

## Executive Summary

Waton saat ini sudah memiliki fondasi parity yang kuat menurut baseline internal:
- `docs/parity/baileys-parity-latest.json` menandai domain utama `done`.
- Scanner parity berhasil lewat preflight (`scripts/preflight_check.py` + `waton/utils/preflight.py`).
- Domain kritikal (messages receive/send, app-state, retry, group signal, connection-core) punya implementasi aktif, bukan placeholder.

Namun, untuk benar-benar selevel Baileys pada kondisi produksi berat, gap terbesar sekarang **bukan lagi kekurangan fitur inti**, melainkan **kedalaman pembuktian parity**.

Masalah inti:
1. Scanner parity saat ini masih dominan heuristik (line ratio + stub markers).
2. Golden tests codec belum mengunci transcript nyata lintas runtime.
3. Unknown payload evolution belum ditangani dengan pipeline telemetry-first yang sistematis.
4. Chaos/replay/live hardening belum menjadi gate wajib harian/mingguan.
5. Governance parity (owner per domain, SLO, drift budget) belum dipaksa oleh CI policy.

Rekomendasi utama:
- Ubah target dari “done by static scan” menjadi “proven by behavioral evidence”.
- Terapkan roadmap 12 bulan berlapis (Quarter 1–4) dengan KPI kuantitatif.
- Jadikan parity release checklist sebagai enforceable policy, bukan hanya dokumen referensi.

## Implementation Status Update (2026-03-01)

### Implemented in current cycle
1. Evidence schema + artifact contract (`docs/parity/evidence-schema.md`, `docs/parity/artifacts/README.md`, `tools/parity/evidence.py`).
2. Fixture index tooling + initial parity fixture manifest (`tools/parity/fixture_index.py`, `tests/fixtures/parity/index.json`).
3. Replay smoke harness + deterministic smoke fixture (`tools/parity/replay_smoke.py`, `tests/fixtures/parity/smoke/message-basic.json`).
4. Evidence-aware parity scan (`tools/parity/scan_baileys_parity.py`, evidence overlay support).
5. Strict preflight evidence validation (`scripts/preflight_check.py`, `waton/utils/preflight.py`).
6. Unknown-event telemetry summarizer + sample artifact (`tools/parity/unknown_telemetry.py`, `docs/parity/artifacts/unknown-telemetry-sample.json`).
7. Governance docs: strict release checklist + ownership/SLA matrix (`docs/runbooks/parity-release-checklist.md`, `docs/runbooks/parity-domain-ownership.md`).
8. Aggregate parity evidence smoke command (`scripts/parity_evidence_smoke.py`).

### Verification snapshot
- `python -m pytest tests -q` -> **PASS** (`312 passed, 2 skipped`).
- `python scripts/preflight_check.py --skip-lint --skip-typecheck` -> **PASS**.
- `python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json --skip-lint --skip-typecheck` -> **PASS**.
- `python scripts/parity_evidence_smoke.py --parity-evidence docs/parity/artifacts/strict-evidence-sample.json` -> **PASS**.
- `python -m ruff check waton tests tools` -> **FAIL** (existing repo-wide lint debt; not introduced by parity-evidence batch).
- `python -m pyright` -> **FAIL** (existing repo-wide typing debt; not introduced by parity-evidence batch).

### Baseline policy sync
- `docs/parity/baileys-parity-latest.json` refreshed from current scanner output (with evidence overlay in strict run).
- `docs/parity/baileys-parity-baseline.json` synchronized from latest (maintainer-approved update for this cycle).

### Remaining closure items
1. Replace sample strict evidence artifact with real CI-produced evidence bundle per release run.
2. Close repo-wide lint/type debt so full strict release gate (`tests + lint + type + strict parity`) becomes fully green.

---

## Current State Snapshot (Evidence)

### A. Scanner/Baseline saat ini
- Sumber: `docs/parity/baileys-parity-latest.json`
- Semua domain utama status `done`.
- Scanner implementation: `tools/parity/scan_baileys_parity.py`
  - `status=done` jika tidak ada marker stub dan line-ratio >= 0.80.
  - Ini berguna untuk hygiene, tapi belum menjamin fidelity protokol nyata.

### B. Preflight gate saat ini
- Entry point: `scripts/preflight_check.py`
- Komponen: tests, lint, typecheck, parity scan, optional live-check.
- Validator (`waton/utils/preflight.py`) menilai domain `done/non-done`.

### C. Reverse foundation sudah ada
- Binary codec core: `waton/protocol/binary_codec.py`
- Protobuf schema + generated: `waton/protocol/protobuf/WAProto.proto`, `WAProto_pb2.py`
- Wire subset untuk handshake: `waton/protocol/protobuf/wire.py`
- Receive pipeline yang cukup luas: `waton/client/messages_recv.py`

### D. Conclusion state
Waton sudah berada di fase **post-foundation parity**. Gap yang tersisa adalah **confidence gap** (seberapa kuat bukti kompatibilitas), bukan semata “fitur belum ada”.

---

## Gap Taxonomy (Master)

### Gap-1: Static Parity Heuristic vs Behavioral Parity Proof
**Current:** scanner berbasis ratio/stub marker.
**Risk:** false confidence; implementasi bisa lolos scan tapi beda behavior di edge frames.
**Target:** domain status diturunkan dari test evidence + replay diff pass-rate, bukan ratio saja.

### Gap-2: Codec Golden Coverage terlalu dangkal
**Current:** golden codec test masih bersifat roundtrip/smoke.
**Risk:** perubahan kecil pada encoding tags/JID/packed values bisa lolos unit test tapi gagal interoperabilitas.
**Target:** curated fixture corpus per domain + byte-level assertions terhadap expected canonical outputs.

### Gap-3: Protobuf Evolution Handling
**Current:** schema sudah ada, tapi unknown-field observability belum jadi first-class pipeline.
**Risk:** WA protocol drift menyebabkan silent degradation (payload tak terbaca penuh) sebelum ketahuan.
**Target:** unknown-field tracker + compatibility report per release.

### Gap-4: Differential Testing lintas runtime belum sistematis
**Current:** referensi Baileys digunakan untuk source/plan parity, belum jadi executable differential harness.
**Risk:** perbedaan semantik muncul pada payload kompleks (newsletter/protocol notifications/retry corners).
**Target:** replay harness yang membandingkan normalized event outputs Waton vs baseline behavior matrix.

### Gap-5: Chaos & reconnect hardening belum enforceable gate
**Current:** ada live check dan integration test, tapi belum menjadi cadence wajib dengan threshold KPI.
**Risk:** reliability regressions muncul di long-run (state drift, duplicate send, retry storms).
**Target:** nightly soak + chaos gates dengan fail budget yang jelas.

### Gap-6: Domain ownership & governance parity belum tegas
**Current:** checklist ada, tapi owner/SLO/domain budget belum terdokumentasi rigid.
**Risk:** gap pindah-pindah tanpa closure; partial debt menumpuk.
**Target:** domain owners + SLA per domain + release blocking policy.

---

## Domain-by-Domain Gap Matrix (Prioritized)

## P0 (must-hardening)

### 1) Binary Codec Fidelity
- Scope: token mapping, JID variants, packed nibble/hex, compress flags, list size, binary lengths.
- Existing assets: `waton/protocol/binary_codec.py`, `tests/unit/test_binary_codec.py`, `tests/golden/*`.
- Gaps:
  - transcript fixtures nyata belum memadai
  - edge-case decoding mismatches tidak diprofilkan terpisah
- Acceptance to close:
  - >= 200 curated frame fixtures across domains
  - zero regression on byte-level compare suite for locked fixture set

### 2) Receive Normalization Fidelity (`messages_recv`)
- Scope: message, receipt, notification, call, ack, ib; retry/placeholder/identity/mediaretry/history sync event shaping.
- Existing: `waton/client/messages_recv.py` + parity extra tests.
- Gaps:
  - mapping parity untuk rare notification subtypes belum terukur coverage heatmap
  - event schema stability versioning belum formal
- Acceptance:
  - event schema snapshot tests versioned
  - coverage report per notification subtype (known/unknown ratio)

### 3) App-state + LT Hash Determinism
- Scope: patch application determinism, mismatch recovery, replay ordering.
- Gaps:
  - drift detector belum menjadi release artifact
- Acceptance:
  - deterministic replay pass on N fixed patch streams
  - drift = 0 for baseline streams

### 4) Retry/Idempotency under failure
- Scope: retry request handling, placeholder resend policy, duplicate prevention.
- Gaps:
  - long-run duplicate suppression threshold belum dinilai statistik
- Acceptance:
  - duplicate visible send rate <= 0.01% under chaos test matrix

## P1 (strong parity confidence)

### 5) Group Signal lifecycle
- Scope: sender-key rotate/update persistence integrity.
- Acceptance:
  - crash/restart consistency tests pass for group key state transitions.

### 6) Media reliability end-to-end
- Scope: upload retry/checksum verification/path refresh.
- Acceptance:
  - fixed success-rate threshold under flaky network simulation.

### 7) Account/device sync semantics
- Scope: companion/account notifications, linked-device consistency.
- Acceptance:
  - deterministic normalized outputs for captured corpus.

## P2 (scale/governance)

### 8) Tooling maturity & developer ergonomics
- fixture tooling, diff tooling, auto-categorization unknowns, triage templates.

### 9) Release governance
- mandatory parity evidence bundle + trend dashboard.

---

## 12-Month Roadmap (Master)

## Quarter 1 (Foundation-to-Evidence transition)
**Objective:** ubah parity “status” menjadi parity “evidence”.

Deliverables:
1. `Parity Evidence Bundle v1` format (JSON + markdown summary):
   - fixture counts, replay pass-rate, unknown field counts, drift metrics.
2. Golden corpus bootstrap (minimum 200 frames) by domain.
3. Differential replay harness skeleton:
   - input captured frame set
   - output normalized event snapshot
   - compare against approved expected outputs.
4. CI stage baru: `parity-evidence-check` (non-blocking first month, blocking by end of Q1).

Exit Criteria:
- Preflight menghasilkan evidence bundle.
- Setiap domain P0 punya minimal fixture baseline.

## Quarter 2 (Hard reliability proof)
**Objective:** buka gap reliability di kondisi gagal jaringan/proses.

Deliverables:
1. Chaos test matrix v1:
   - disconnect storms, delayed acks, reconnect loops, partial sync failures.
2. Drift detector untuk app-state/retry pipelines.
3. Unknown-field telemetry collector:
   - agregasi tag/type unknown per run.
4. Domain owner assignments + SLO draft.

Exit Criteria:
- Nightly chaos jobs aktif.
- Drift/duplicate metrics tercatat historis.

## Quarter 3 (Cross-runtime differential maturity)
**Objective:** parity comparison lintas runtime jadi rutin dan actionable.

Deliverables:
1. Differential harness v2 (domain-specific comparators).
2. Schema/versioning policy untuk normalized events.
3. Auto-generated parity regressions issue template.
4. Release blocker rule for P0 domains if pass-rate below threshold.

Exit Criteria:
- Differential pass-rate >= target P0.
- Unknown-event classification latency < agreed SLA.

## Quarter 4 (Production parity governance)
**Objective:** parity jadi operational discipline, bukan proyek ad-hoc.

Deliverables:
1. Parity dashboard (trend): pass-rate, drift, unknowns, regression rate.
2. Release checklist v2 tied to CI evidence artifacts.
3. Annual parity review + domain recalibration.
4. Documentation freeze quality gate for protocol-critical changes.

Exit Criteria:
- 3 release cycles berturut-turut lolos parity governance tanpa emergency rollback domain P0.

---

## KPI & Success Criteria

### Core KPI
1. **Replay Pass Rate (P0):** >= 99.5%
2. **Unknown Event Rate:** turun kuartalan, target < 0.5% event stream pada Q4
3. **State Drift Incidents:** 0 di release gate suite
4. **Duplicate Send Rate under chaos:** <= 0.01%
5. **Regression Escape Rate (post-release parity bug):** turun kuartalan

### Tooling KPI
1. Fixture growth rate (net fixtures/domain/month)
2. Differential test runtime budget (tetap dalam CI window)
3. Mean time to classify unknown payload

---

## Tooling Gap Detail + Implementation Targets

### 1) Parity Scanner Evolution
Current scanner (`tools/parity/scan_baileys_parity.py`) perlu ditingkatkan dari:
- static line ratio + stub scan
menjadi:
- evidence-aware scanner:
  - reads fixture pass-rate
  - unknown-field counts
  - drift metrics
  - domain threshold policy.

### 2) Preflight Evolution
Current `scripts/preflight_check.py` perlu menambahkan:
- artifact emission path standard (`docs/parity/artifacts/<date>/<run-id>/...`)
- mandatory parity evidence validation for release mode
- strict/soft modes:
  - soft for dev branch
  - strict for release branch.

### 3) Fixture & Replay Toolchain
Tambahkan tooling:
- capture sanitizer (remove sensitive values)
- fixture indexer (domain/type/tags)
- replay runner with deterministic clocks/ids
- comparator module (per domain rules)

### 4) Unknown Field Intelligence
Tambahkan:
- unknown field extractor (proto + binary tags)
- clustering by signature
- triage report auto-generated

---

## Risk Register (Top)

1. **False parity confidence from static metrics**
   - Mitigation: evidence-based status.
2. **Protocol drift from upstream WhatsApp changes**
   - Mitigation: unknown telemetry + fast triage loop.
3. **Test suite explosion (runtime too long)**
   - Mitigation: layered gates (smoke vs full vs nightly).
4. **Sensitive payload handling in fixtures**
   - Mitigation: sanitizer + policy enforcement before commit.
5. **Ownership ambiguity**
   - Mitigation: assign owner per domain with SLA.

---

## Governance Model (Recommended)

Per domain P0/P1 tetapkan:
- Owner (primary + backup)
- SLOs (pass rate/drift/latency)
- Release blocking threshold
- Runbook link
- Escalation path

Suggested governance cadence:
- Weekly parity triage (30-45 min)
- Monthly domain health review
- Quarterly roadmap recalibration

---

## Immediate Next Actions (30 days)

1. Define parity evidence schema v1 (`docs/parity/evidence-schema.md`).
2. Upgrade scanner to support evidence inputs (non-breaking mode).
3. Create initial fixture backlog by domain (P0 first).
4. Add replay smoke job to CI.
5. Publish domain ownership table in runbook.

---

## Decision Log (for this report)

1. Keep current “done baseline” as foundation indicator, not final parity verdict.
2. Shift release confidence from code-size proxy to behavior evidence.
3. Prioritize P0 reliability domains before expanding feature breadth.
4. Enforce governance with objective thresholds.

---

# Appendix A — Evidence Model Specification (Draft)

Required artifact fields:
- `run_id`, `commit_sha`, `timestamp`
- `domains[]`:
  - `name`
  - `status` (`done`/`partial`/`missing`)
  - `fixture_total`
  - `fixture_passed`
  - `replay_pass_rate`
  - `unknown_event_count`
  - `unknown_field_count`
  - `drift_count`
  - `duplicate_send_count`

Derived status policy example:
- `done` only if:
  - pass_rate >= threshold
  - unknown_count <= threshold
  - drift_count == 0

---

# Appendix B — Domain-Level Comparator Rules (Draft)

Comparator should ignore non-deterministic fields:
- timestamps with tolerated window
- generated IDs (unless semantic identity required)
- runtime metadata not protocol-relevant

Comparator should strictly match:
- event type
- protocol action classification
- critical IDs/jids relationships
- ack/retry semantics
- app-state version/hash transitions

---

# Appendix C — Fixture Curation Policy

1. Capture from authorized local sessions only.
2. Sanitize all user identifiers/media URLs where possible.
3. Tag each fixture:
   - domain
   - source flow
   - expected event class
   - sensitivity level
4. No raw secret material committed.
5. Each new protocol bugfix must include fixture reproducer.

---

# Appendix D — CI/CD Gate Blueprint

Stages:
1. `unit-fast`
2. `protocol-replay-smoke`
3. `parity-scan-static`
4. `parity-evidence-check`
5. `chaos-nightly` (scheduled)

Blocking policy:
- PR to main: block on 1-4
- Release tag: block on 1-5 + release checklist verification

---

# Appendix E — 12-Month Milestone Checklist

## Q1 Checklist
- [ ] Evidence schema approved
- [ ] Scanner v2 (static + evidence)
- [ ] 200 fixtures curated
- [ ] Replay smoke CI live

## Q2 Checklist
- [ ] Chaos matrix v1
- [ ] Drift detector integrated
- [ ] Unknown telemetry report live
- [ ] Domain owners assigned

## Q3 Checklist
- [ ] Differential harness v2
- [ ] Event schema version policy
- [ ] Regression automation templates
- [ ] P0 threshold enforcement

## Q4 Checklist
- [ ] Parity dashboard live
- [ ] Release checklist v2 enforced
- [ ] 3 stable release cycles achieved
- [ ] Annual parity review complete
