from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from tools.parity.canonicalize import canonicalize_event, canonicalize_stream
from tools.parity.differential_harness import compare_parity_streams
from tools.parity.oracle_runner import load_oracle_stream


def test_canonicalize_event_normalizes_nondeterministic_fields() -> None:
    event = {
        "scenario_id": "s1",
        "timestamp": 1700000000,
        "wire_signature": "message/text",
        "semantic_payload": {"text": "hello", "nonce": "abc"},
    }
    out = canonicalize_event(event)
    assert out["timestamp"] == "<normalized>"
    assert out["semantic_payload"]["nonce"] == "<normalized>"
    assert out["wire_signature"] == "message/text"


def test_compare_parity_streams_reports_no_drift_when_equal() -> None:
    oracle = [
        {
            "scenario_id": "s1",
            "phase": "recv",
            "event_type": "message",
            "wire_signature": "message/text",
            "semantic_payload": {"text": "hello"},
            "order_index": 0,
        }
    ]
    waton = canonicalize_stream(oracle)
    result = compare_parity_streams(oracle, waton)
    assert result["wire_pass"] is True
    assert result["behavior_pass"] is True
    assert result["drift_summary"]["count"] == 0


def test_compare_parity_streams_reports_wire_and_behavior_drift() -> None:
    oracle = [
        {
            "scenario_id": "s1",
            "phase": "recv",
            "event_type": "message",
            "wire_signature": "message/text",
            "semantic_payload": {"text": "hello"},
            "order_index": 0,
        }
    ]
    waton = [
        {
            "scenario_id": "s1",
            "phase": "recv",
            "event_type": "message",
            "wire_signature": "message/image",
            "semantic_payload": {"text": "hi"},
            "order_index": 0,
        }
    ]
    result = compare_parity_streams(oracle, waton)
    assert result["wire_pass"] is False
    assert result["behavior_pass"] is False
    assert result["drift_summary"]["count"] == 1


def test_load_oracle_stream_reads_json_array(tmp_path: Path) -> None:
    p = tmp_path / "oracle.json"
    p.write_text(json.dumps([{"wire_signature": "message/text"}]), encoding="utf-8")
    stream = load_oracle_stream(p)
    assert isinstance(stream, list)
    assert stream[0]["wire_signature"] == "message/text"


def test_load_oracle_stream_rejects_non_array(tmp_path: Path) -> None:
    p = tmp_path / "oracle.json"
    p.write_text(json.dumps({"wire_signature": "message/text"}), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON array"):
        load_oracle_stream(p)
