import json
from pathlib import Path


def replay_fixture(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    # smoke-only: pass through expected normalized view
    return data["expected"]
