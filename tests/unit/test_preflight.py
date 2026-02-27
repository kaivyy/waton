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
