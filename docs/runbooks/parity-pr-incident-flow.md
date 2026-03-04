# Parity PR Incident Flow

This runbook defines mandatory response flow when hard-block parity checks fail on a pull request.

## Trigger

A parity incident is triggered when any required parity check fails:

1. `parity-oracle-main-sync`
2. `parity-diff-wire`
3. `parity-diff-behavior`
4. `parity-strict-evidence`

## Classification

Classify failure into one of:

- `wire_drift`: wire-signature mismatch vs oracle output
- `behavior_drift`: semantic outcome mismatch vs oracle output
- `evidence_threshold_fail`: strict evidence threshold/shape failure

## Immediate Actions

1. Attach artifact links from `docs/parity/artifacts/<run-id>/...`.
2. Open issue under `parity/<domain>` based on ownership matrix.
3. Notify primary owner and backup owner from domain ownership runbook.
4. Mark PR as blocked until parity checks return green.

## Escalation

- P0 domains: acknowledge in 24h, mitigation/fix in current PR.
- P1 domains: acknowledge in 72h, mitigation/fix before merge.

## Closure Criteria

Incident closes only when:

1. Failed parity checks are green in fresh CI run.
2. Evidence bundle includes required strict keys.
3. Differential artifacts are attached and reviewable.
4. Release notes include accepted unknown-event budget decisions (if applicable).
