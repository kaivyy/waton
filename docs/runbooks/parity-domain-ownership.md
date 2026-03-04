# Parity Domain Ownership and SLA Matrix

This runbook defines ownership, backup ownership, and service-level targets for parity-critical domains.

Parity policy in this repo is a **hard-block PR gate** for the hybrid strict parity definition: **wire parity + behavior parity + strict evidence parity**.

## Ownership Matrix

| Domain | Priority | Primary Owner | Backup Owner | Runbook | Escalation Path |
|---|---|---|---|---|---|
| messages-recv | P0 | Runtime Maintainer | Protocol Maintainer | `docs/runbooks/parity-release-checklist.md` | Create issue `parity/messages-recv` + notify release captain |
| app-state-sync | P0 | Protocol Maintainer | Runtime Maintainer | `docs/runbooks/parity-release-checklist.md` | Create issue `parity/app-state-sync` + notify release captain |
| retry-manager | P0 | Runtime Maintainer | QA Maintainer | `docs/runbooks/parity-release-checklist.md` | Create issue `parity/retry-manager` + notify release captain |
| group-signal | P0 | Crypto Maintainer | Runtime Maintainer | `docs/runbooks/parity-release-checklist.md` | Create issue `parity/group-signal` + notify release captain |
| messages-send | P1 | Runtime Maintainer | Protocol Maintainer | `docs/runbooks/parity-release-checklist.md` | Create issue `parity/messages-send` + notify release captain |
| connection-core | P1 | Runtime Maintainer | Infra Maintainer | `docs/runbooks/parity-release-checklist.md` | Create issue `parity/connection-core` + notify release captain |

## SLA / SLO Targets

| Domain | Replay Pass Rate (min) | Drift Count (max) | Unknown Event Handling SLA | Release Gate |
|---|---:|---:|---|---|
| P0 domains | 99.5% | 0 | 24 hours | Blocking |
| P1 domains | 99.5% | 0 | 72 hours | Blocking |

## Release Blocking Policy

A release and PR merge are blocked when any of the following conditions is true:

1. Any hybrid strict parity leg fails (`wire parity`, `behavior parity`, or `strict evidence parity`).
2. Any P0/P1 domain evidence is missing required strict fields.
3. Replay pass rate is below threshold.
4. Drift count is non-zero.
5. Unknown events exceed current budget and no accepted mitigation is documented in release notes.
6. Strict evidence `commit_sha` does not match the CI expected commit SHA for the PR/release run.

Required PR check names for hard-block policy:
- `parity-oracle-main-sync`
- `parity-diff-wire`
- `parity-diff-behavior`
- `parity-strict-evidence`

This policy is intentional hard-block behavior: parity checks are merge requirements, not advisory signals.

## Governance Cadence

1. Weekly parity triage (owner + backup owner).
2. Monthly domain health review for trend and budget updates.
3. Quarterly recalibration of thresholds and ownership.
