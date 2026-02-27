"""Run release preflight gates in one command."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from waton.utils.preflight import (  # noqa: E402
    PreflightConfig,
    build_preflight_commands,
    load_parity_report,
    validate_parity_report,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Waton release preflight checks.")
    parser.add_argument(
        "--baileys-src",
        default=str((ROOT_DIR.parent / "Baileys" / "src").resolve()),
        help="Path to Baileys src directory",
    )
    parser.add_argument("--waton-root", default="waton", help="Path to waton package root")
    parser.add_argument(
        "--parity-out",
        default="docs/parity/baileys-parity-latest.json",
        help="Path for generated parity report",
    )
    parser.add_argument("--skip-lint", action="store_true", help="Skip ruff gate")
    parser.add_argument("--skip-typecheck", action="store_true", help="Skip pyright gate")
    parser.add_argument("--with-live", action="store_true", help="Run live check gate")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Copy latest parity report to docs/parity/baileys-parity-baseline.json on success",
    )
    return parser


def _run_command(name: str, args: list[str]) -> int:
    resolved_args = list(args)
    if resolved_args and resolved_args[0] == "python":
        resolved_args[0] = sys.executable
    print(f"[preflight] running {name}: {' '.join(resolved_args)}")
    proc = subprocess.run(resolved_args, cwd=ROOT_DIR)
    if proc.returncode != 0:
        print(f"[preflight] FAILED {name} (exit={proc.returncode})")
        return proc.returncode
    print(f"[preflight] passed {name}")
    return 0


def main() -> int:
    args = _build_parser().parse_args()
    config = PreflightConfig(
        waton_root=args.waton_root,
        baileys_src=args.baileys_src,
        parity_out=args.parity_out,
        include_live_check=args.with_live,
        include_lint=not args.skip_lint,
        include_typecheck=not args.skip_typecheck,
    )

    commands = build_preflight_commands(config)
    for command in commands:
        code = _run_command(command.name, command.args)
        if code != 0:
            return code

    report = load_parity_report(config.parity_out)
    issues = validate_parity_report(report)
    if issues:
        print("[preflight] parity validation failed:")
        for issue in issues:
            print(f"  - {issue}")
        return 1
    print("[preflight] parity validation passed")

    if args.update_baseline:
        baseline_path = ROOT_DIR / "docs" / "parity" / "baileys-parity-baseline.json"
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT_DIR / config.parity_out, baseline_path)
        print(f"[preflight] baseline updated: {baseline_path}")

    print("[preflight] ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
