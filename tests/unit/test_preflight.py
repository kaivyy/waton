from __future__ import annotations

import json
from pathlib import Path

from waton.utils.preflight import PreflightConfig, build_preflight_commands, load_parity_report, validate_parity_report


def test_build_preflight_commands_default() -> None:
    config = PreflightConfig(baileys_src="C:/Baileys/src")
    commands = build_preflight_commands(config)
    names = [cmd.name for cmd in commands]
    assert names == ["tests", "ruff", "pyright", "parity-scan"]
    parity_cmd = commands[-1].args
    assert "--baileys" in parity_cmd
    assert "C:/Baileys/src" in parity_cmd
    assert "--evidence" not in parity_cmd


def test_build_preflight_commands_with_live_and_skips() -> None:
    config = PreflightConfig(
        include_lint=False,
        include_typecheck=False,
        include_live_check=True,
        baileys_src="C:/Baileys/src",
    )
    commands = build_preflight_commands(config)
    names = [cmd.name for cmd in commands]
    assert names == ["tests", "parity-scan", "live-check"]
    assert commands[-1].required is False


def test_build_preflight_commands_adds_parity_evidence_arg() -> None:
    config = PreflightConfig(
        baileys_src="C:/Baileys/src",
        parity_evidence="docs/parity/evidence.json",
    )
    commands = build_preflight_commands(config)
    parity_cmd = next(cmd for cmd in commands if cmd.name == "parity-scan").args
    assert "--evidence" in parity_cmd
    assert "docs/parity/evidence.json" in parity_cmd


def test_validate_parity_report_flags_non_done() -> None:
    report = {
        "domains": {
            "messages-recv": {"status": "done"},
            "messages-send": {"status": "partial"},
            "retry-manager": {"status": "missing"},
        }
    }
    issues = validate_parity_report(report)
    assert "messages-send: status=partial" in issues
    assert "retry-manager: status=missing" in issues
    assert all("messages-recv" not in issue for issue in issues)


def test_load_parity_report_and_validate_done(tmp_path: Path) -> None:
    report_path = tmp_path / "parity.json"
    report_path.write_text(
        json.dumps(
            {
                "domains": {
                    "messages-recv": {"status": "done"},
                    "messages-send": {"status": "done"},
                }
            }
        ),
        encoding="utf-8",
    )
    report = load_parity_report(str(report_path))
    issues = validate_parity_report(report)
    assert issues == []


def test_validate_parity_report_strict_passes_with_required_evidence() -> None:
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
    issues = validate_parity_report(report, strict=True)
    assert issues == []


def test_validate_parity_report_strict_fails_when_replay_below_threshold() -> None:
    report = {
        "domains": {
            "messages-recv": {
                "status": "done",
                "evidence": {
                    "replay_pass_rate": 0.99,
                    "unknown_event_count": 0,
                    "drift_count": 0,
                    "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
                    "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
                },
            }
        }
    }
    issues = validate_parity_report(report, strict=True)
    assert any("replay_pass_rate" in issue for issue in issues)


def test_validate_parity_report_strict_fails_when_drift_nonzero() -> None:
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
                    "drift_count": 1,
                    "wire_diff_artifact": "docs/parity/artifacts/r1/wire/messages-recv.json",
                    "behavior_diff_artifact": "docs/parity/artifacts/r1/behavior/messages-recv.json",
                },
            }
        },
    }
    issues = validate_parity_report(report, strict=True)
    assert any("drift_count" in issue for issue in issues)


def test_release_checklist_mentions_expected_commit_sha_enforcement() -> None:
    text = (
        Path(__file__).resolve().parents[2] / "docs" / "runbooks" / "parity-release-checklist.md"
    ).read_text(encoding="utf-8")
    assert "expected commit sha" in text.lower()
