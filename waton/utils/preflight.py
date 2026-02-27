"""Release preflight helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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

    commands.append(
        PreflightCommand(
            name="parity-scan",
            args=[
                "python",
                "-m",
                "tools.parity.scan_baileys_parity",
                "--waton",
                config.waton_root,
                "--baileys",
                config.baileys_src,
                "--out",
                config.parity_out,
            ],
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


def validate_parity_report(report: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    domains = report.get("domains")
    if not isinstance(domains, dict):
        return ["parity report missing domains map"]

    for domain, payload in domains.items():
        if not isinstance(payload, dict):
            issues.append(f"{domain}: invalid payload")
            continue
        status = payload.get("status")
        if status == "done":
            continue
        issues.append(f"{domain}: status={status}")
    return issues
