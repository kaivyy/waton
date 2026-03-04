from __future__ import annotations

from typing import Any

from tools.parity.canonicalize import canonicalize_stream


def compare_parity_streams(
    oracle_stream: list[dict[str, Any]],
    waton_stream: list[dict[str, Any]],
) -> dict[str, Any]:
    oracle = canonicalize_stream(oracle_stream)
    waton = canonicalize_stream(waton_stream)

    drifts: list[dict[str, Any]] = []
    max_len = max(len(oracle), len(waton))

    for idx in range(max_len):
        oracle_event = oracle[idx] if idx < len(oracle) else None
        waton_event = waton[idx] if idx < len(waton) else None
        if oracle_event != waton_event:
            drifts.append(
                {
                    "order_index": idx,
                    "oracle": oracle_event,
                    "waton": waton_event,
                }
            )

    wire_pass = all(
        drift["oracle"] is not None
        and drift["waton"] is not None
        and drift["oracle"].get("wire_signature") == drift["waton"].get("wire_signature")
        for drift in drifts
    )
    behavior_pass = all(
        drift["oracle"] is not None
        and drift["waton"] is not None
        and drift["oracle"].get("semantic_payload") == drift["waton"].get("semantic_payload")
        for drift in drifts
    )

    if not drifts:
        wire_pass = True
        behavior_pass = True

    return {
        "wire_pass": wire_pass,
        "behavior_pass": behavior_pass,
        "drift_summary": {
            "count": len(drifts),
            "items": drifts,
        },
    }
