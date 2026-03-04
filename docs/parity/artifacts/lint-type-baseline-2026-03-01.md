# Lint/type baseline (2026-03-01)

Generated from:
- `.tmp/ruff-current.json` via `python -m ruff check waton tests tools --output-format json > .tmp/ruff-current.json || true`
- `.tmp/pyright-current.json` via `python -m pyright --outputjson > .tmp/pyright-current.json || true`

Note: raw baseline artifacts keep tool-native paths (often absolute local paths). This markdown summary presents normalized repo-relative paths (for example, `tests/unit/test_app.py` and `waton/app/app.py`) for readability.

## Ruff baseline

- Total issues: **0**

### Top rules by count

- _(none; lint clean)_

### Top files by count

- _(none; lint clean)_

## Pyright baseline

- Total diagnostics: **0**
- Files analyzed: **59**

### Top rules by count

- _(none; typecheck clean)_

### Top files by count

- _(none; typecheck clean)_

## RED/GREEN evidence (Task 1 follow-up)

### RED (expected fail before artifacts are present)

Command:
- `python -m pytest tests/unit/test_lint_type_baseline_artifacts.py::test_current_lint_type_snapshots_exist -v`

Result:
- **FAILED** with `AssertionError` at `assert Path(".tmp/ruff-current.json").exists()` (`False`).

### GREEN (pass with artifacts restored)

Command:
- `python -m pytest tests/unit/test_lint_type_baseline_artifacts.py::test_current_lint_type_snapshots_exist -v`

Result:
- **PASSED** (`1 passed`).

## Task 6 final non-skip gate verification (2026-03-03)

Executed command suite (no lint/type skips):
- `python -m pytest tests -q` -> `314 passed, 2 skipped`
- `python -m ruff check waton tests tools` -> `All checks passed!`
- `python -m pyright` -> `0 errors, 0 warnings, 0 informations`
- `python scripts/preflight_check.py --parity-strict --parity-evidence docs/parity/artifacts/strict-evidence-sample.json` -> `[preflight] ALL CHECKS PASSED`
- `python scripts/parity_evidence_smoke.py --parity-evidence docs/parity/artifacts/strict-evidence-sample.json` -> `[parity-evidence-smoke] ALL CHECKS PASSED`

Final baseline status for release gate:
- Ruff: **0 issues**
- Pyright: **0 diagnostics**

## Task 1 scope

Task 1-owned files:
- `tests/unit/test_lint_type_baseline_artifacts.py`
- `docs/parity/artifacts/lint-type-baseline-2026-03-01.md`
- `.tmp/ruff-current.json`
- `.tmp/pyright-current.json`
