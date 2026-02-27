# Waton Parity Release Checklist

Use this checklist before claiming Baileys-equivalent parity for a release candidate.

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

## 4) Live Reliability

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

## 5) Release Hygiene

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
