from tools.parity.differential_harness import compare_parity_streams
from tools.parity.evidence import build_empty_evidence


def test_evidence_schema_has_required_fields() -> None:
    evidence = build_empty_evidence(run_id="r1", commit_sha="abc123")
    assert "run_id" in evidence
    assert "commit_sha" in evidence
    assert "domains" in evidence
    assert "timestamp" in evidence


def test_evidence_schema_domain_entries_can_store_diff_artifact_pointers() -> None:
    evidence = build_empty_evidence(run_id="r1", commit_sha="abc123")
    evidence["domains"]["messages-recv"] = {
        "replay_pass_rate": 1.0,
        "unknown_event_count": 0,
        "drift_count": 0,
        "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
        "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
    }

    domain = evidence["domains"]["messages-recv"]
    assert "wire_diff_artifact" in domain
    assert "behavior_diff_artifact" in domain
    assert domain["wire_diff_artifact"].endswith("wire/messages-recv.json")
    assert domain["behavior_diff_artifact"].endswith("behavior/messages-recv.json")


def test_compare_parity_streams_reports_match_and_drift() -> None:
    oracle_stream = [
        {
            "scenario_id": "s1",
            "phase": "recv",
            "event_type": "message",
            "wire_signature": "message/text",
            "semantic_payload": {"text": "hello"},
            "order_index": 0,
        }
    ]

    waton_stream_ok = [
        {
            "scenario_id": "s1",
            "phase": "recv",
            "event_type": "message",
            "wire_signature": "message/text",
            "semantic_payload": {"text": "hello"},
            "order_index": 0,
        }
    ]
    waton_stream_drift = [
        {
            "scenario_id": "s1",
            "phase": "recv",
            "event_type": "message",
            "wire_signature": "message/image",
            "semantic_payload": {"text": "hi"},
            "order_index": 0,
        }
    ]

    ok = compare_parity_streams(oracle_stream, waton_stream_ok)
    assert ok["wire_pass"] is True
    assert ok["behavior_pass"] is True
    assert ok["drift_summary"]["count"] == 0

    drift = compare_parity_streams(oracle_stream, waton_stream_drift)
    assert drift["wire_pass"] is False
    assert drift["behavior_pass"] is False
    assert drift["drift_summary"]["count"] == 1
