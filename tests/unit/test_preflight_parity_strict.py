from __future__ import annotations

from waton.utils.preflight import validate_parity_report


def test_validate_parity_report_fails_when_done_without_evidence() -> None:
    report = {"domains": {"messages-recv": {"status": "done"}}}
    issues = validate_parity_report(report, strict=True)
    assert issues
    assert any("messages-recv" in issue for issue in issues)
    assert any("missing evidence" in issue for issue in issues)


def test_validate_parity_report_strict_requires_diff_artifact_pointers() -> None:
    report = {
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": 1.0,
                    "unknown_event_count": 0,
                    "drift_count": 0,
                },
            }
        }
    }
    issues = validate_parity_report(report, strict=True)
    assert any("missing evidence" in issue for issue in issues)


def test_validate_parity_report_strict_rejects_blank_diff_artifact_paths() -> None:
    report = {
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": 1.0,
                    "unknown_event_count": 0,
                    "drift_count": 0,
                    "wire_diff_artifact": "",
                    "behavior_diff_artifact": "  ",
                },
            }
        }
    }
    issues = validate_parity_report(report, strict=True)
    assert any("invalid wire_diff_artifact" in issue for issue in issues)
    assert any("invalid behavior_diff_artifact" in issue for issue in issues)



def test_validate_parity_report_strict_requires_top_level_evidence_metadata() -> None:
    report = {
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
        }
    }
    issues = validate_parity_report(report, strict=True)
    assert any("run_id" in issue for issue in issues)
    assert any("commit_sha" in issue for issue in issues)
    assert any("timestamp" in issue for issue in issues)



def test_validate_parity_report_strict_rejects_commit_sha_mismatch() -> None:
    report = {
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
    issues = validate_parity_report(report, strict=True, expected_commit_sha="def456")
    assert any("commit_sha mismatch" in issue for issue in issues)



def test_validate_parity_report_strict_accepts_valid_full_report() -> None:
    report = {
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
    issues = validate_parity_report(report, strict=True, expected_commit_sha="abc123")
    assert issues == []


def test_validate_parity_report_strict_rejects_bool_replay_rate() -> None:
    report = {
        "run_id": "r1",
        "commit_sha": "abc123",
        "timestamp": "2026-03-03T00:00:00+00:00",
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": True,
                    "unknown_event_count": 0,
                    "drift_count": 0,
                    "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
                    "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
                },
            }
        },
    }
    issues = validate_parity_report(report, strict=True)
    assert any("invalid replay_pass_rate" in issue for issue in issues)


def test_validate_parity_report_strict_rejects_bool_drift_count() -> None:
    report = {
        "run_id": "r1",
        "commit_sha": "abc123",
        "timestamp": "2026-03-03T00:00:00+00:00",
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": 1.0,
                    "unknown_event_count": 0,
                    "drift_count": False,
                    "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
                    "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
                },
            }
        },
    }
    issues = validate_parity_report(report, strict=True)
    assert any("invalid drift_count" in issue for issue in issues)


def test_validate_parity_report_strict_rejects_out_of_range_replay_rate() -> None:
    report = {
        "run_id": "r1",
        "commit_sha": "abc123",
        "timestamp": "2026-03-03T00:00:00+00:00",
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": 1.2,
                    "unknown_event_count": 0,
                    "drift_count": 0,
                    "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
                    "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
                },
            }
        },
    }
    issues = validate_parity_report(report, strict=True)
    assert any("out of range" in issue for issue in issues)
