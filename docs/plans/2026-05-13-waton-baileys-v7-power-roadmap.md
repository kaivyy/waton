# Waton Baileys V7 Power Roadmap Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Membuat Waton lebih kuat mengikuti arah Baileys v7/rc11 tanpa mematahkan logika runtime, public API, atau behavior default yang sudah ada.

**Architecture:** Semua peningkatan dilakukan secara additive dan compatibility-first. Baseline behavior Waton dibekukan lewat characterization tests, lalu fitur parity Baileys v7 ditambahkan sebagai metadata, storage capability, optional event fields, feature flags, dan retry/resilience helpers sebelum mengubah jalur aktif. Setiap milestone wajib punya parity evidence, rollback path, dan test yang membuktikan behavior lama tetap sama.

**Tech Stack:** Python 3.11+, pytest, Waton client/protocol/utils modules, JSON/SQLite storage backends, parity tooling (`tools/parity/*`), Baileys local oracle at `C:\Users\Arvy Kairi\Desktop\whatsapp\Baileys`, optional Rust crypto bridge in `rust/`.

---

## Non-Negotiable Constraints

1. **Do not change default logic first.** Existing message send/receive, ACK, retry, storage, and event dispatch behavior must remain default until a milestone explicitly graduates from shadow mode.
2. **Add before replace.** New Baileys v7 capabilities start as additive fields, optional helpers, diagnostics, or feature-flagged paths.
3. **Parity evidence before activation.** A new behavior can become default only after unit tests, fixture replay, and Baileys differential evidence agree.
4. **Public API compatibility.** Existing imports, method signatures, callback behavior, and event payload keys remain valid.
5. **One risk domain per PR.** LID/tctoken, retry, media, app-state, ACK, and protocol codec changes must not be bundled together.

---

## Current Baseline

Waton already has the core shape of a Python Baileys-inspired client:

- `waton/client/client.py`: connection lifecycle, WebSocket, Noise handshake, QR/pairing, stanza routing, keepalive, ACK/retry boundaries.
- `waton/client/messages.py`: outgoing message creation, USync device lookup, Signal session assertion, encryption, relay.
- `waton/client/messages_recv.py`: message, receipt, notification, call, ACK, and IB decoding.
- `waton/utils/*`: content decoding, protocol message processing, app-state helpers, LTHash, event buffering, crypto, auth.
- `waton/protocol/*`: binary node codec, Noise, Signal repository, protobuf, app-state, group cipher.
- `tools/parity/*` and `docs/parity/*`: parity scan, evidence, fixtures, differential harness foundations.

Baileys v7/rc11 adds useful direction for Waton:

- stronger LID/PN mapping and Signal session migration;
- tctoken lifecycle for trusted-contact/message-account-restriction recovery;
- retry/resend flow with key bundles and sender-key distribution messages;
- app-state and history-sync resilience;
- offline node batching and event-buffer hardening;
- richer presence, call, newsletter, MEX, devices, and reachout/limit notifications;
- media memory improvements and safer per-recipient encryption handling;
- more complete parity/e2e test harness.

---

## Roadmap Overview

| Phase | Theme | Default Logic Impact | Main Outcome |
| --- | --- | --- | --- |
| 0 | Baseline Freeze | None | Existing behavior documented and guarded by tests |
| 1 | Parity Intelligence | None | Baileys v7/rc11 delta tracked as machine-readable matrix |
| 2 | Additive Data Model | None | Storage can hold LID, tctoken, device-list, retry metadata |
| 3 | Receive-Pipeline Power | Shadow/additive | New notifications decoded without changing handlers |
| 4 | Retry & Resend Resilience | Feature flag | Safer retry metadata and key-bundle support |
| 5 | App-State & Offline Resilience | Feature flag | Bad records skipped/isolated, offline queue can batch |
| 6 | Send/Media Robustness | Feature flag | Per-recipient failure reporting, media memory safeguards |
| 7 | Protocol & WAProto Hygiene | None first | Version/schema drift visible before it breaks runtime |
| 8 | Developer UX & CI Gates | None | Doctor, dashboard, parity reports, release checklist |
| 9 | Graduation | Controlled | Selected shadow features become default after evidence |

---

## Phase 0: Baseline Freeze and Compatibility Contract

**Purpose:** Prevent accidental logic changes while making the project more powerful.

**Files:**
- Modify: `docs/parity/evidence-schema.md`
- Modify: `docs/runbooks/parity-release-checklist.md`
- Modify: `tests/unit/test_client.py`
- Modify: `tests/unit/test_messages.py`
- Modify: `tests/unit/test_messages_recv.py`
- Modify: `tests/unit/test_storage.py`
- Modify: `tests/unit/test_public_exports.py`

**Work:**
1. Add a "compatibility contract" document section listing current public imports, event names, and default ACK/retry behavior.
2. Add characterization tests for current message send path, receive dispatch, storage read/write, public exports, and retry defaults.
3. Mark all new v7-inspired behavior as disabled unless explicitly configured.

**Acceptance:**
```bash
python -m pytest tests/unit/test_public_exports.py tests/unit/test_client.py tests/unit/test_messages.py tests/unit/test_messages_recv.py tests/unit/test_storage.py -q
```

Expected: all existing behavior remains green before any feature work starts.

---

## Phase 1: Baileys V7 Delta Matrix

**Purpose:** Track what Baileys changed and what Waton supports without relying on memory or vague parity claims.

**Files:**
- Create: `docs/parity/baileys-v7-delta-matrix.md`
- Create: `docs/parity/baileys-v7-roadmap-status.json`
- Modify: `tools/parity/scan_baileys_parity.py`
- Test: `tests/unit/test_parity_scan.py`

**Work:**
1. Create a matrix with domains: LID, tctoken, retry, app-state, offline queue, media, WABinary/JID, notifications, newsletter, business, groups, presence.
2. For each domain, record:
   - Baileys source files;
   - Waton source files;
   - status: `missing`, `shadow`, `partial`, `default`, `not-applicable`;
   - risk level;
   - test coverage;
   - activation gate.
3. Extend parity scan output with v7 status without changing runtime code.

**Acceptance:**
```bash
python -m pytest tests/unit/test_parity_scan.py -q
python -m tools.parity.scan_baileys_parity --waton waton --baileys "C:\Users\Arvy Kairi\Desktop\whatsapp\Baileys\src" --out docs/parity/baileys-parity-latest.json
```

Expected: a report is generated and no runtime module behavior changes.

---

## Phase 2: Additive Storage and Identity Model

**Purpose:** Prepare storage for Baileys v7 identity concepts while keeping old auth/session logic unchanged.

**Files:**
- Modify: `waton/core/jid.py`
- Modify: `waton/core/entities.py`
- Modify: `waton/infra/storage_json.py`
- Modify: `waton/infra/storage_sqlite.py`
- Modify: `waton/protocol/signal_repo.py`
- Test: `tests/unit/test_jid.py`
- Test: `tests/unit/test_storage.py`
- Test: `tests/unit/test_signal.py`

**Work:**
1. Add typed helpers for PN, LID, hosted, interop, bot, newsletter, group, and status JIDs.
2. Add storage namespaces for:
   - `lid_mapping`;
   - `device_list`;
   - `tc_token`;
   - `message_retry_state`;
   - `identity_change_state`.
3. Keep storage reads optional and no-op if data is absent.
4. Do not migrate existing sessions automatically in this phase.

**Acceptance:**
```bash
python -m pytest tests/unit/test_jid.py tests/unit/test_storage.py tests/unit/test_signal.py -q
```

Expected: new data can round-trip, old storage files remain readable.

---

## Phase 3: Receive-Pipeline Shadow Decoders

**Purpose:** Decode more Baileys v7 notifications without changing user callbacks.

**Files:**
- Modify: `waton/client/messages_recv.py`
- Modify: `waton/utils/process_message.py`
- Modify: `waton/utils/protocol_message.py`
- Modify: `waton/core/events.py`
- Test: `tests/unit/test_messages_recv.py`
- Test: `tests/unit/test_messages_recv_parity_extra.py`
- Test: `tests/unit/test_protocol_message.py`

**Work:**
1. Add shadow decode for:
   - devices notification;
   - identity change;
   - MEX linked profile/LID mapping notification;
   - reachout timelock;
   - new chat/message-account restriction;
   - newsletter multiple messages per notification stanza;
   - enriched call fields;
   - group online count in presence.
2. Store unknown or unsupported fields in metadata instead of dropping them.
3. Emit existing event names unchanged. New fields must be optional.

**Acceptance:**
```bash
python -m pytest tests/unit/test_messages_recv.py tests/unit/test_messages_recv_parity_extra.py tests/unit/test_protocol_message.py -q
```

Expected: old fixtures decode identically; new fixtures expose optional metadata.

---

## Phase 4: Retry, Resend, and Tctoken Reliability

**Purpose:** Make retry flows more durable while keeping legacy retry behavior as the default until proven.

**Files:**
- Modify: `waton/client/retry_manager.py`
- Modify: `waton/client/messages.py`
- Modify: `waton/client/messages_recv.py`
- Create: `waton/client/tc_token.py`
- Modify: `waton/protocol/group_cipher.py`
- Test: `tests/unit/test_retry_manager.py`
- Test: `tests/unit/test_messages_send_protocol.py`
- Create: `tests/unit/test_tc_token.py`

**Work:**
1. Add tctoken store helpers:
   - expiration;
   - pruning;
   - issuance target JID resolution;
   - sender timestamp tracking.
2. Add retry metadata for:
   - key bundle processing;
   - sender-key distribution message embedding;
   - phone request dedupe;
   - expired status retry skip.
3. Feature flag new retry behavior behind `enable_baileys_v7_retry`.
4. Keep current retry path untouched when flag is off.

**Acceptance:**
```bash
python -m pytest tests/unit/test_retry_manager.py tests/unit/test_messages_send_protocol.py tests/unit/test_tc_token.py -q
```

Expected: feature-flag-off behavior matches baseline; feature-flag-on tests validate new metadata flow.

---

## Phase 5: App-State, History Sync, and Offline Queue Resilience

**Purpose:** Prevent one bad sync record from aborting the whole sync path.

**Files:**
- Modify: `waton/protocol/app_state.py`
- Modify: `waton/utils/chat_utils.py`
- Modify: `waton/utils/event_buffer.py`
- Create: `waton/utils/offline_node_processor.py`
- Test: `tests/unit/test_app_state.py`
- Test: `tests/unit/test_lt_hash.py`
- Test: `tests/unit/test_event_pipeline.py`
- Create: `tests/unit/test_offline_node_processor.py`

**Work:**
1. Add error classification for missing app-state keys, HMAC failure, AES decrypt failure, and irrecoverable sync failures.
2. Add optional resilience mode that skips bad records and reports partial state.
3. Add offline node batching with event-loop yielding.
4. Keep current synchronous path as default until parity evidence approves switching.

**Acceptance:**
```bash
python -m pytest tests/unit/test_app_state.py tests/unit/test_lt_hash.py tests/unit/test_event_pipeline.py tests/unit/test_offline_node_processor.py -q
```

Expected: baseline behavior still passes; resilience mode has isolated failure tests.

---

## Phase 6: Send and Media Robustness

**Purpose:** Improve high-volume reliability without changing message content semantics.

**Files:**
- Modify: `waton/client/messages.py`
- Modify: `waton/client/media.py`
- Modify: `waton/utils/media_utils.py`
- Modify: `waton/utils/message_content.py`
- Test: `tests/unit/test_messages.py`
- Test: `tests/unit/test_messages_send_protocol.py`
- Test: `tests/unit/test_media_reliability.py`
- Test: `tests/unit/test_message_content.py`

**Work:**
1. Add per-recipient encryption result reporting in diagnostics.
2. Fail only when all recipients fail under feature flag; keep old failure handling by default.
3. Add streaming/media memory guardrails for upload/download.
4. Preserve caller-provided waveform and media metadata.
5. Add album message planning fixtures, but keep send support disabled until protocol parity is proven.

**Acceptance:**
```bash
python -m pytest tests/unit/test_messages.py tests/unit/test_messages_send_protocol.py tests/unit/test_media_reliability.py tests/unit/test_message_content.py -q
```

Expected: existing message payload generation remains byte/field compatible.

---

## Phase 7: Protocol, WAProto, and Version Hygiene

**Purpose:** Detect protocol drift early.

**Files:**
- Modify: `waton/protocol/binary_codec.py`
- Modify: `waton/protocol/constants.py`
- Modify: `waton/protocol/protobuf/WAProto.proto`
- Modify: `waton/protocol/protobuf/WAProto_pb2.py`
- Create: `tools/parity/wa_version_tracker.py`
- Test: `tests/unit/test_binary_codec.py`
- Test: `tests/unit/test_protobuf_wire.py`
- Test: `tests/golden/test_golden_codec.py`

**Work:**
1. Add parity checks for FB, interop, hosted, and empty-string JID codec behavior.
2. Add version tracker comparing Waton WA version/schema against Baileys local `src/Defaults/baileys-version.json` and `WAProto/WAProto.proto`.
3. Do not regenerate protobuf in the same PR as behavior changes.
4. Keep generated file changes isolated and reviewed separately.

**Acceptance:**
```bash
python -m pytest tests/unit/test_binary_codec.py tests/unit/test_protobuf_wire.py tests/golden/test_golden_codec.py -q
```

Expected: drift is reported clearly; codec behavior remains compatible with existing golden fixtures.

---

## Phase 8: Developer UX, Dashboard, and CI

**Purpose:** Make the stronger internals visible and maintainable.

**Files:**
- Modify: `scripts/preflight_check.py`
- Modify: `scripts/parity_evidence_smoke.py`
- Modify: `tools/dashboard/server.py`
- Modify: `tools/dashboard/state.py`
- Modify: `tools/dashboard/static/dashboard.js`
- Modify: `tools/dashboard/templates/index.html`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Test: `tests/unit/test_preflight.py`
- Test: `tests/unit/test_dashboard.py`
- Test: `tests/unit/test_parity_evidence_smoke_script.py`

**Work:**
1. Add `preflight` sections for:
   - Baileys version drift;
   - feature-flag status;
   - storage capability status;
   - parity evidence freshness.
2. Add dashboard panels for connection, retry, tctoken, LID mapping, and unknown telemetry.
3. Add CI gate that requires baseline tests before any feature flag can graduate.
4. Update docs with "safe upgrade path" for users.

**Acceptance:**
```bash
python -m pytest tests/unit/test_preflight.py tests/unit/test_dashboard.py tests/unit/test_parity_evidence_smoke_script.py -q
```

Expected: developer visibility improves without runtime behavior changes.

---

## Phase 9: Graduation Policy

**Purpose:** Decide when a shadow feature becomes default.

**Files:**
- Modify: `docs/runbooks/parity-release-checklist.md`
- Modify: `docs/runbooks/parity-domain-ownership.md`
- Modify: `docs/parity/baileys-v7-delta-matrix.md`
- Modify: `waton/defaults/config.py`
- Test: domain-specific tests from the graduating feature

**Graduation Requirements:**
1. Feature has been available behind a flag for at least one release cycle.
2. Baseline tests pass with flag off and flag on.
3. Baileys differential fixtures pass for the domain.
4. Unknown telemetry does not increase.
5. Rollback is a config flip, not a code revert.
6. Changelog names the default change explicitly.

**Acceptance:**
```bash
python -m pytest tests -q
python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json
```

Expected: selected feature can become default with documented evidence and rollback.

---

## Suggested Execution Order

1. **Week 1:** Phase 0 and Phase 1 only. No runtime changes. Freeze behavior and make delta visible.
2. **Week 2:** Phase 2 storage/JID groundwork. Still no active behavior changes.
3. **Week 3:** Phase 3 receive shadow decoders. Add metadata and fixtures.
4. **Week 4:** Phase 4 retry/tctoken behind feature flag.
5. **Week 5:** Phase 5 app-state/offline resilience behind feature flag.
6. **Week 6:** Phase 6 media/send robustness behind feature flag.
7. **Week 7:** Phase 7 protocol/version drift tooling and isolated WAProto updates.
8. **Week 8:** Phase 8 dashboard/CI/docs.
9. **After evidence:** Phase 9 graduation, one feature at a time.

---

## Risk Register

| Risk | Impact | Mitigation |
| --- | --- | --- |
| LID/PN mapping corrupts sessions | Login/send failures | Store mappings additively; no automatic migration in Phase 2 |
| Retry changes create resend loops | Account risk, duplicate sends | Feature flag, retry counters, phone request dedupe, expired status skip |
| ACK behavior drift | Ban/delivery risk | Characterization tests and explicit ACK policy docs |
| App-state resilience hides real corruption | Silent data loss | Emit structured warnings and partial-state evidence |
| WAProto regeneration mixes with logic | Hard review, regressions | Generated-only PRs |
| Media optimization changes payload | Send/download regressions | Golden fixtures and metadata preservation tests |
| Dashboard exposes sensitive state | Privacy/security risk | Redact tokens, keys, JIDs by default |

---

## Definition of "More Powerful" Without Logic Breakage

Waton is considered more powerful when it can:

- detect Baileys protocol drift before users hit runtime failures;
- store and inspect richer identity/retry/tctoken metadata;
- decode new WhatsApp/Baileys notification shapes without crashing;
- isolate bad sync/offline records instead of losing whole batches;
- report per-recipient send/encryption diagnostics;
- expose operational state in preflight/dashboard;
- keep current user code running unchanged.

This roadmap deliberately separates **capability** from **default behavior**. Capability lands first; default behavior changes only after evidence.

---

## Final Verification Command Set

Run these before claiming a milestone complete:

```bash
python -m pytest tests -q
python -m ruff check waton tests tools scripts
python -m pyright
python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json
```

If local environment cannot run the full set, record the exact command, exit code, and blocker in the milestone notes.
