# Parity Artifacts

This directory contains **artifacts referenced by parity evidence bundles**.

## Contract

- Artifacts are stored under `docs/parity/artifacts/`.
- Evidence JSON should reference artifacts by relative filename/path within this directory.
- Artifacts are intended to be human-reviewable (JSON, text) and kept reasonably small.

## Policy

- Strict/release CI parity gates must use **CI-generated evidence**.
- Sample evidence is for local/dev smoke checks only.

Examples (non-exhaustive):

- unknown-event telemetry summaries
- replay smoke outputs
- drift reports
- differential wire parity outputs
- differential behavior parity outputs
