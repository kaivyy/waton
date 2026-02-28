import json
from pathlib import Path


def replay_fixture(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Fixture JSON must be an object")

    if "expected" not in data:
        raise ValueError("Fixture JSON missing top-level 'expected'")

    expected = data["expected"]
    if not isinstance(expected, dict):
        raise ValueError("Fixture JSON 'expected' must be an object")

    # smoke-only: pass through expected normalized view
    return expected
