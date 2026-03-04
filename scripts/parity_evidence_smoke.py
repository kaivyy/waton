"""Run parity evidence smoke pipeline commands."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]


def _default_baileys_src() -> str:
    return str((ROOT_DIR.parent / "Baileys" / "src").resolve())


def build_commands(
    *,
    baileys_src: str,
    evidence_path: str | None = None,
    expected_commit_sha: str | None = None,
) -> list[dict[str, object]]:
    parity_scan_args = [
        "python",
        "-m",
        "tools.parity.scan_baileys_parity",
        "--waton",
        "waton",
        "--baileys",
        baileys_src,
        "--out",
        "docs/parity/baileys-parity-latest.json",
    ]
    if evidence_path:
        parity_scan_args.extend(["--evidence", evidence_path])

    commands: list[dict[str, object]] = [
        {
            "name": "parity-oracle-main-sync",
            "args": [
                "python",
                "-c",
                "from pathlib import Path; import sys; p=Path(sys.argv[1]).resolve(); print(p); raise SystemExit(0 if p.is_dir() else 1)",
                baileys_src,
            ],
        },
        {
            "name": "parity-scan",
            "args": parity_scan_args,
        },
        {
            "name": "parity-diff-wire",
            "args": ["python", "-m", "pytest", "tests/unit/test_parity_differential_harness.py", "-q"],
        },
        {
            "name": "parity-diff-behavior",
            "args": ["python", "-m", "pytest", "tests/unit/test_parity_evidence_pipeline.py", "-q"],
        },
        {
            "name": "parity-replay-smoke",
            "args": ["python", "-m", "pytest", "tests/unit/test_parity_replay_smoke.py", "-q"],
        },
    ]

    if evidence_path:
        strict_args = [
            "python",
            "scripts/preflight_check.py",
            "--parity-strict",
            "--parity-evidence",
            evidence_path,
            "--skip-lint",
            "--skip-typecheck",
        ]
        if expected_commit_sha:
            strict_args.extend(["--expected-commit-sha", expected_commit_sha])
        commands.append(
            {
                "name": "parity-strict-evidence",
                "args": strict_args,
            }
        )

    return commands


def _run(name: str, args: list[str]) -> int:
    print(f"[parity-evidence-smoke] running {name}: {' '.join(args)}")
    resolved_args = list(args)
    if resolved_args and resolved_args[0] == "python":
        resolved_args[0] = sys.executable
    proc = subprocess.run(resolved_args, cwd=ROOT_DIR)
    if proc.returncode != 0:
        print(f"[parity-evidence-smoke] FAILED {name} (exit={proc.returncode})")
        return proc.returncode
    print(f"[parity-evidence-smoke] passed {name}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run parity evidence smoke pipeline commands.")
    parser.add_argument(
        "--baileys-src",
        default=_default_baileys_src(),
        help="Path to Baileys src directory",
    )
    parser.add_argument(
        "--parity-evidence",
        default=None,
        help="Optional strict parity evidence JSON path",
    )
    parser.add_argument(
        "--expected-commit-sha",
        default=None,
        help="Optional expected commit SHA for strict parity evidence validation",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    for command in build_commands(
        baileys_src=args.baileys_src,
        evidence_path=args.parity_evidence,
        expected_commit_sha=args.expected_commit_sha,
    ):
        name = str(command["name"])
        cmd_args = [str(x) for x in command["args"]]
        code = _run(name, cmd_args)
        if code != 0:
            return code
    print("[parity-evidence-smoke] ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
