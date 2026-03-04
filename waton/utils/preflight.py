"""Release preflight helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast


@dataclass
class PreflightCommand:
    name: str
    args: list[str]
    required: bool = True


@dataclass
class PreflightConfig:
    waton_root: str = "waton"
    baileys_src: str = "../Baileys/src"
    parity_out: str = "docs/parity/baileys-parity-latest.json"
    parity_evidence: str | None = None
    include_live_check: bool = False
    include_lint: bool = True
    include_typecheck: bool = True


def build_preflight_commands(config: PreflightConfig) -> list[PreflightCommand]:
    commands: list[PreflightCommand] = [
        PreflightCommand(name="tests", args=["python", "-m", "pytest", "tests", "-q"]),
    ]
    if config.include_lint:
        commands.append(
            PreflightCommand(
                name="ruff",
                args=["python", "-m", "ruff", "check", "waton", "tests", "tools"],
            )
        )
    if config.include_typecheck:
        commands.append(PreflightCommand(name="pyright", args=["python", "-m", "pyright"]))

    parity_args = [
        "python",
        "-m",
        "tools.parity.scan_baileys_parity",
        "--waton",
        config.waton_root,
        "--baileys",
        config.baileys_src,
        "--out",
        config.parity_out,
    ]
    if config.parity_evidence:
        parity_args.extend(["--evidence", config.parity_evidence])

    commands.append(
        PreflightCommand(
            name="parity-scan",
            args=parity_args,
        )
    )
    if config.include_live_check:
        commands.append(
            PreflightCommand(
                name="live-check",
                args=["python", "scripts/live_check.py"],
                required=False,
            )
        )
    return commands


def load_parity_report(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_parity_report(
    report: dict[str, Any],
    *,
    strict: bool = False,
    expected_commit_sha: str | None = None,
) -> list[str]:
    issues: list[str] = []
    if strict:
        for field in ("run_id", "commit_sha", "timestamp"):
            value = report.get(field)
            if not isinstance(value, str) or not value.strip():
                issues.append(f"parity report missing or invalid {field}")

        if expected_commit_sha is not None:
            commit_sha = report.get("commit_sha")
            if isinstance(commit_sha, str) and commit_sha.strip() and commit_sha != expected_commit_sha:
                issues.append(
                    f"commit_sha mismatch: report={commit_sha!r} expected={expected_commit_sha!r}"
                )

    domains = report.get("domains")
    if not isinstance(domains, dict):
        issues.append("parity report missing domains map")
        return issues

    domains_map = cast("dict[str, object]", domains)
    required_evidence_keys = [
        "replay_pass_rate",
        "unknown_event_count",
        "drift_count",
        "wire_diff_artifact",
        "behavior_diff_artifact",
    ]

    for domain, payload in domains_map.items():
        if not isinstance(payload, dict):
            issues.append(f"{domain}: invalid payload")
            continue
        payload_typed = cast("dict[str, Any]", payload)
        status = payload_typed.get("status")
        if status == "done":
            if strict:
                evidence_obj = payload_typed.get("evidence", {})
                evidence_map: dict[str, Any] = (
                    cast("dict[str, Any]", evidence_obj) if isinstance(evidence_obj, dict) else {}
                )
                missing = [k for k in required_evidence_keys if k not in evidence_map]
                if missing:
                    issues.append(f"{domain}: missing evidence {missing}")
                    continue

                replay = evidence_map.get("replay_pass_rate")
                drift = evidence_map.get("drift_count")
                wire_artifact = evidence_map.get("wire_diff_artifact")
                behavior_artifact = evidence_map.get("behavior_diff_artifact")
                if isinstance(replay, bool) or not isinstance(replay, (int, float)):
                    issues.append(f"{domain}: invalid replay_pass_rate={replay!r}")
                    continue
                if replay < 0.0 or replay > 1.0:
                    issues.append(f"{domain}: replay_pass_rate={replay} out of range [0.0, 1.0]")
                elif replay < 0.995:
                    issues.append(f"{domain}: replay_pass_rate={replay} below 0.995")
                if isinstance(drift, bool) or not isinstance(drift, int):
                    issues.append(f"{domain}: invalid drift_count={drift!r}")
                    continue
                if drift != 0:
                    issues.append(f"{domain}: drift_count={drift} expected 0")
                if not isinstance(wire_artifact, str) or not wire_artifact.strip():
                    issues.append(f"{domain}: invalid wire_diff_artifact={wire_artifact!r}")
                if not isinstance(behavior_artifact, str) or not behavior_artifact.strip():
                    issues.append(f"{domain}: invalid behavior_diff_artifact={behavior_artifact!r}")
            continue
        issues.append(f"{domain}: status={status}")
    return issues
