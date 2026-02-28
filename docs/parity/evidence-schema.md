# Parity Evidence Schema

This document defines the JSON schema for Waton parity **evidence bundles**.

The intent is to make parity claims verifiable by attaching behavioral evidence (replays, drift checks, telemetry) to parity reports.

## Top-level object

Required fields:

- `run_id` (string): unique identifier for a single evidence run (CI run id, timestamped id, etc.)
- `commit_sha` (string): git commit SHA associated with the evidence run
- `timestamp` (string): ISO-8601 timestamp (UTC recommended) for when the evidence bundle was generated
- `domains` (object/map): per-domain evidence payloads keyed by domain name

### Example (minimal)

```json
{
  "run_id": "r1",
  "commit_sha": "abc123",
  "timestamp": "2026-03-01T00:00:00+00:00",
  "domains": {}
}
```

## Domains

`domains` is an object where each key is a domain identifier (e.g. `messages-recv`, `binary-codec`) and each value is an object containing evidence for that domain.

Evidence payloads are intentionally extensible. Domain payloads may include (non-exhaustive):

- replay results (pass rates, failure samples)
- unknown-event telemetry counts
- drift detection counts or summaries
- artifact references (file names under `docs/parity/artifacts/`)
