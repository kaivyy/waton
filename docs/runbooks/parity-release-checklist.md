# Waton Parity Release Checklist

Use this checklist before claiming Baileys-equivalent parity for a release candidate.

For this repository, a claim of **100% parity** means the release candidate passes the hybrid strict gate: **wire parity + behavior parity + strict evidence parity**.

## 1) Code and Architecture

1. No critical-path stub markers in `waton/client`, `waton/protocol`, `waton/utils`.
2. Receive pipeline uses persist-before-emit order.
3. App-state patch logic and LT hash are deterministic and tested.
4. Retry manager and idempotency logic are enabled for message sends.
5. Group signal sender-key flow has no placeholder values.

## 2) Verification Gates

1. `python -m pytest tests -q`
2. `python -m ruff check waton tests tools`
3. `python -m pyright`

Shortcut:

```bash
python scripts/preflight_check.py
```

All gates must pass in clean environment.

## 3) Parity Scan

Run:

```bash
python tools/parity/scan_baileys_parity.py \
  --waton waton \
  --baileys ..\Baileys\src \
  --out docs/parity/baileys-parity-baseline.json
```

Required:
1. Critical domains are not `missing`.
2. Any `partial` domain must have explicit follow-up tasks in `docs/plans`.

## 4) Parity Evidence Release Gate (Strict)

This strict gate is one leg of the hybrid 100% parity definition (`wire + behavior + strict evidence`).

Required evidence bundle must follow [docs/parity/evidence-schema.md](../parity/evidence-schema.md).

For each domain with `status=done`, evidence payload must include:
1. `replay_pass_rate`
2. `unknown_event_count`
3. `drift_count`
4. `wire_diff_artifact`
5. `behavior_diff_artifact`

Minimum release thresholds (policy):
1. `replay_pass_rate >= 0.995` (**enforced by strict preflight**)
2. `drift_count == 0` (**enforced by strict preflight**)
3. `unknown_event_count` is explicitly reviewed and accepted in release notes.

Strict gate command:

```bash
python scripts/preflight_check.py --parity-strict --parity-evidence <path-to-evidence-json>
```

CI strict gate command (with expected commit sha enforcement):

```bash
python scripts/preflight_check.py --parity-strict --parity-evidence <path-to-evidence-json> --expected-commit-sha <commit-sha>
```

Required:
1. Command exits with status 0.
2. No domain-level `missing evidence [...]` issues are printed.
3. No `commit_sha mismatch` issues are printed when CI expected commit sha is provided.

## 5) Live Reliability

Run:

```bash
set WATON_RUN_LIVE_RELIABILITY=1
set WATON_AUTH_DB=waton_live.db
set WATON_TEST_JID=628xxxxxxxxxx@s.whatsapp.net
set WATON_TEST_TEXT=live reliability check
python -m pytest tests/integration/test_reliability_live.py -v
```

Alternative one-command smoke check:

```bash
python scripts/live_check.py --auth-db waton_live.db --test-jid 628xxxxxxxxxx@s.whatsapp.net --test-text "live reliability check"
```

Required:
1. Pair/connect works.
2. `send_text` receives message ACK for sent `message_id` (if `WATON_TEST_JID` is set).
3. Reconnect cycle works without state drift.
4. Only one active client session is running for the same auth DB during test
   (avoid `440 conflict` false negatives).

## 6) Release Hygiene

1. `CHANGELOG.md` updated under `Unreleased`.
2. Parity plan status updated in `docs/plans`.
3. Release notes include known partial domains and mitigation.
4. Packaging artifacts are runtime-only:

```bash
python -m pip wheel . --no-deps -w .tmp-wheel
python -m maturin sdist --manifest-path Cargo.toml --out .tmp-sdist
```

Required:
1. Wheel does not include `docs/`, `examples/`, `tests/`, `tools/`.
2. Source distribution does not include `docs/`, `examples/`, `tests/`, `tools/`.
