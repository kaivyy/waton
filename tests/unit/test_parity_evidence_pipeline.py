from __future__ import annotations

from tools.parity.differential_harness import compare_parity_streams
from waton.utils.preflight import validate_parity_report


def _base_report() -> dict:
    return {
        "run_id": "r1",
        "commit_sha": "abc123",
        "timestamp": "2026-03-03T00:00:00+00:00",
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": 1.0,
                    "unknown_event_count": 0,
                    "drift_count": 0,
                    "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
                    "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
                },
            }
        },
    }


def test_strict_parity_evidence_pipeline_passes_when_diff_is_clean() -> None:
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
            "wire_signature": "message/text",
            "semantic_payload": {"text": "hello"},
            "order_index": 0,
        }
    ]

    diff = compare_parity_streams(oracle, waton)
    report = _base_report()
    report["domains"]["messages-recv"]["evidence"]["drift_count"] = diff["drift_summary"]["count"]

    issues = validate_parity_report(report, strict=True)
    assert issues == []


def test_strict_parity_evidence_pipeline_fails_when_diff_has_drift() -> None:
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
            "semantic_payload": {"text": "bye"},
            "order_index": 0,
        }
    ]

    diff = compare_parity_streams(oracle, waton)
    report = _base_report()
    report["domains"]["messages-recv"]["evidence"]["drift_count"] = diff["drift_summary"]["count"]

    issues = validate_parity_report(report, strict=True)
    assert any("drift_count" in issue for issue in issues)
