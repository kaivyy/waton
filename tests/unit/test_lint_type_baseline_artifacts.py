import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _load_json(relative_path: str) -> Any:
    file_path = ROOT / relative_path
    assert file_path.exists(), (
        f"missing artifact: {relative_path}. "
        "generate with: python -m ruff check waton tests tools --output-format json > .tmp/ruff-current.json || true; "
        "python -m pyright --outputjson > .tmp/pyright-current.json || true"
    )
    return json.loads(file_path.read_text(encoding="utf-8"))


def test_current_lint_type_snapshots_exist() -> None:
    ruff_payload = _load_json(".tmp/ruff-current.json")
    pyright_payload = _load_json(".tmp/pyright-current.json")

    assert isinstance(ruff_payload, list)
    if ruff_payload:
        first_issue = ruff_payload[0]
        assert isinstance(first_issue, dict)
        assert "code" in first_issue
        assert "filename" in first_issue

    assert isinstance(pyright_payload, dict)
    diagnostics = pyright_payload.get("generalDiagnostics")
    summary = pyright_payload.get("summary")
    assert isinstance(diagnostics, list)
    assert isinstance(summary, dict)
    error_count = summary.get("errorCount")
    assert isinstance(error_count, int)
    assert error_count == len(diagnostics)
