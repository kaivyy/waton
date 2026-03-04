import subprocess
import sys
from pathlib import Path

from scripts.parity_evidence_smoke import build_commands


def test_build_commands_contains_parity_stages() -> None:
    cmds = build_commands(baileys_src="C:/Baileys/src")
    names = [c["name"] for c in cmds]
    assert "parity-oracle-main-sync" in names
    assert "parity-scan" in names
    assert "parity-diff-wire" in names
    assert "parity-diff-behavior" in names
    assert "parity-replay-smoke" in names

    sync_cmd = next(c for c in cmds if c["name"] == "parity-oracle-main-sync")
    assert sync_cmd["args"][0] == "python"


def test_build_commands_adds_strict_stage_when_evidence_path_present() -> None:
    evidence_path = "docs/parity/artifacts/strict-evidence-sample.json"
    cmds = build_commands(baileys_src="C:/Baileys/src", evidence_path=evidence_path)
    names = [c["name"] for c in cmds]
    assert "parity-strict-evidence" in names

    strict_cmd = next(c for c in cmds if c["name"] == "parity-strict-evidence")
    assert evidence_path in strict_cmd["args"]


def test_build_commands_strict_stage_includes_expected_commit_sha() -> None:
    evidence_path = "docs/parity/artifacts/strict-evidence-sample.json"
    cmds = build_commands(
        baileys_src="C:/Baileys/src",
        evidence_path=evidence_path,
        expected_commit_sha="deadbeef",
    )
    strict_cmd = next(c for c in cmds if c["name"] == "parity-strict-evidence")
    assert "--expected-commit-sha" in strict_cmd["args"]
    assert "deadbeef" in strict_cmd["args"]


def test_artifacts_readme_mentions_ci_generated_evidence_requirement() -> None:
    text = Path("docs/parity/artifacts/README.md").read_text(encoding="utf-8").lower()
    assert "ci-generated evidence" in text
    assert "local/dev" in text
    assert "smoke checks only" in text


def test_parity_oracle_main_sync_returns_non_zero_for_invalid_baileys_src() -> None:
    cmds = build_commands(baileys_src="C:/path/that/does/not/exist")
    sync_cmd = next(c for c in cmds if c["name"] == "parity-oracle-main-sync")

    args = [str(x) for x in sync_cmd["args"]]
    if args and args[0] == "python":
        args[0] = sys.executable

    proc = subprocess.run(args, capture_output=True, text=True)

    assert proc.returncode != 0
