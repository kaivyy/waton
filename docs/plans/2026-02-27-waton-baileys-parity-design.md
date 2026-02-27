# Waton 0-100 Parity Design (Baileys-Equivalent)

Date: 2026-02-27  
Source of truth repository: `C:\Users\Arvy Kairi\Desktop\whatsapp\waton`

## 1) Goal and Scope

This document defines how `waton` reaches "100", where "100" means production reliability and behavioral parity with Baileys for core WhatsApp Web multi-device operations.

Primary goal:
- Make `waton` as strong as Baileys in reliability, state consistency, and protocol correctness.

Constraint:
- Keep `waton` Python-first for developer ergonomics.
- Keep Rust as internal helper only (crypto/perf), never as a runtime burden for end users.

Non-goal:
- Copying Baileys API shape 1:1 before reliability core is complete.

## 2) Definition of "100" (Parity Completion)

`waton` is considered parity-complete only when all items below are true:

1. Receive/send/app-state/group-signal/retry pipelines have no critical stubs.
2. Live reconnect and sync are stable without state drift.
3. End-to-end behavior under failure (network drops/timeouts/restarts) is deterministic.
4. Core parity matrix items are `done` with acceptance tests.
5. CI and release gates enforce regression protection.

Parity completion is not "many features exist". It is "features exist and survive production conditions".

## 3) Clean Architecture Baseline

The architecture follows strict boundaries:

1. `Transport Layer` (`infra/websocket.py`, noise frame boundary)
- Responsibilities: websocket I/O, frame ingress/egress, transport lifecycle.
- No business rules in this layer.

2. `Protocol Layer` (`protocol/*`)
- Responsibilities: binary codec, WA protobuf wire mapping, signal/noise primitives, patch protocols.
- Pure protocol logic, no app workflow decisions.

3. `Domain/Orchestration Layer` (`client/*`)
- Responsibilities: connection state machine, message send/receive orchestration, retry/app-state flows.
- This is where policy decisions live.

4. `Application Layer` (`app/*`)
- Responsibilities: developer-facing API, routers, middleware, context helpers.
- No protocol internals exposed directly.

5. `Persistence Layer` (`infra/storage_*`)
- Responsibilities: auth/session/key/state durability with atomic updates.
- Must support crash-safe commit semantics for critical state transitions.

Dependency rule:
- Outer layers depend on inner contracts.
- Inner layers never depend on app-facing modules.

## 4) Current Parity Matrix

Status labels:
- `done`: parity behavior + tests complete
- `partial`: working subset, not production-complete
- `missing`: critical path not implemented

| Domain | Baseline | Status | Gap |
|---|---|---|---|
| Receive pipeline (`messages-recv`) | Baileys `Socket/messages-recv.ts` | partial | no full decrypt-normalize-persist-emit pipeline |
| App-state sync and LT hash | Baileys `sync-action-utils`, `lt-hash`, `history` | partial/missing | patch apply and hash recovery incomplete |
| Retry manager | Baileys `message-retry-manager` | missing | no centralized bounded retry + dedup orchestration |
| Group Signal | Baileys `Signal/Group/*` | partial/stub | sender-key logic still incomplete in critical paths |
| Identity change handling | Baileys `identity-change-handler` | partial | mismatch/rekey policy not fully hardened |
| Media reliability | Baileys `messages-media` | partial | upload/download/reupload resilience incomplete |
| USync/device fanout | Baileys `WAUSync/*` | partial | protocol coverage not yet complete |
| API breadth (groups/privacy/profile/chat modify) | Baileys socket surface | partial | several operations still placeholders |

## 5) Implementation Phases and Acceptance Gates

### Phase 1: Receive Core Parity
- Build full inbound pipeline: node -> decrypt -> decode -> normalize -> persist -> emit.
- Acceptance:
  - incoming private/group text stable across reconnect
  - no lost events during restart simulation

### Phase 2: App-State Sync + LT Hash
- Implement deterministic patch apply with version/index checks.
- Add hash mismatch recovery via snapshot/full sync.
- Acceptance:
  - no state drift after repeated reconnect + incremental patches

### Phase 3: Retry Manager + Idempotency
- Add bounded backoff retry engine with dedup keys.
- Persist retry context for crash-safe resend policy.
- Acceptance:
  - fault injection tests pass (timeout/drop)
  - no duplicate visible sends

### Phase 4: Group Signal Full
- Replace remaining sender-key stubs with full implementation.
- Ensure atomic persistence for group key updates.
- Acceptance:
  - stable group send/receive under reconnect and device changes

### Phase 5: Identity/Device + Media Hardening
- Implement robust identity mismatch and rekey policy.
- Harden media upload/download/reupload and checksum paths.
- Acceptance:
  - no session corruption on identity changes
  - expired media reupload flow works

### Phase 6: API Breadth and Production Hardening
- Complete API parity targets and remove placeholder behavior.
- Finalize observability, docs, and release gates.
- Acceptance:
  - parity matrix core domains all `done`
  - soak/chaos tests pass

## 6) Testing Strategy (0-100)

1. Unit deterministic tests
- codec, noise, signal, lt-hash, retry scheduler, identity policy

2. Protocol integration tests
- frame transcript replay with expected event/state order

3. Live integration tests
- pair -> send -> receive -> receipt -> reconnect -> resync

4. Soak + chaos tests
- 6-12h stability with disconnects/delays/frame drops/restarts

CI gates:
1. PR gate: lint + type + unit + protocol integration
2. Nightly gate: live integration subset
3. Release gate: full soak + parity checklist

## 7) Maintainability Standards

To keep the codebase easy to maintain:

1. No hidden cross-layer coupling
- every cross-layer interaction must pass explicit interfaces.

2. Typed contracts and explicit events
- event payloads must be versioned and validated.

3. Small cohesive modules
- each module has one responsibility and test ownership.

4. No placeholder in critical path
- stubs allowed only in clearly isolated non-critical feature branches.

5. Crash-safe persistence
- key/session/state updates must be atomic where protocol correctness depends on it.

6. Observability by default
- connection and protocol state transitions must emit structured logs.

7. Test ownership
- each new protocol behavior includes unit + integration coverage.

## 8) Changelog Policy (Mandatory)

Every parity-affecting change must update `CHANGELOG.md` under `Unreleased`.

Required format:
1. `Added` for new protocol/API capabilities
2. `Changed` for behavior or policy changes
3. `Fixed` for reliability/protocol bug fixes
4. `Docs` for architecture/runbook/testing documentation updates
5. `Tests` (optional section) for new parity gates and regressions

Entry requirements:
- mention impacted module (`client/messages`, `protocol/signal_repo`, etc.)
- mention user-visible outcome
- mention parity domain impacted (`receive`, `retry`, `app-state`, etc.)

No release is cut if changelog and parity matrix are out of sync.

## 9) Execution Cadence

Weekly loop:
1. pick highest-risk parity domain
2. implement smallest complete slice
3. add regression tests
4. run gates
5. update parity matrix + changelog
6. merge only when acceptance criteria are green

Definition of done per slice:
- code implemented
- tests added and passing
- docs updated
- changelog updated
- parity matrix status updated
