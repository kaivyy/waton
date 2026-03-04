from __future__ import annotations


def summarize_unknown_events(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        event_type = row.get("event_type")
        if isinstance(event_type, str) and event_type.startswith("unknown"):
            counts[event_type] = counts.get(event_type, 0) + 1
    return counts
