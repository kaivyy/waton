from __future__ import annotations

from copy import deepcopy
from typing import Any

_NONDTERMINISTIC_KEYS = {
    "timestamp",
    "timestamp_ms",
    "nonce",
    "message_id",
    "id",
    "run_id",
    "commit_sha",
}


def _canonicalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key in sorted(value.keys()):
            if key in _NONDTERMINISTIC_KEYS:
                normalized[key] = "<normalized>"
            else:
                normalized[key] = _canonicalize_value(value[key])
        return normalized
    if isinstance(value, list):
        return [_canonicalize_value(item) for item in value]
    return value


def canonicalize_event(event: dict[str, Any]) -> dict[str, Any]:
    return _canonicalize_value(deepcopy(event))


def canonicalize_stream(stream: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [canonicalize_event(item) for item in stream]
