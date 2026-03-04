from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


def run_oracle_command(command: list[str], *, cwd: str | None = None) -> list[dict[str, Any]]:
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
    payload = json.loads(proc.stdout)
    if not isinstance(payload, list):
        raise ValueError("oracle output must be a JSON array")
    return payload


def load_oracle_stream(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("oracle stream fixture must be a JSON array")
    return payload
