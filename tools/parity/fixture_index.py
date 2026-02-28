import json
from pathlib import Path
from typing import Any


def load_fixture_index(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
