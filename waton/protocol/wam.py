"""Practical WAM telemetry subset encoder."""

from __future__ import annotations

from typing import Any


def _typed_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return f"b:{1 if value else 0}"
    if isinstance(value, int):
        return f"i:{value}"
    if isinstance(value, float):
        return f"f:{value}"
    return f"s:{value}"


def encode_wam_event(*, event_name: str, event_code: int, fields: dict[str, Any]) -> bytes:
    if not isinstance(event_name, str) or not event_name.strip():
        raise ValueError("event_name must be a non-empty string")

    rows = [
        "WAM1",
        f"event:{event_name.strip()}",
        f"code:{int(event_code)}",
    ]
    for key in sorted(fields.keys()):
        rows.append(f"{key}={_typed_scalar(fields[key])}")

    return "\n".join(rows).encode("utf-8")
