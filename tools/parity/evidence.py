from __future__ import annotations

from datetime import UTC, datetime


def build_empty_evidence(run_id: str, commit_sha: str) -> dict:
    return {
        "run_id": run_id,
        "commit_sha": commit_sha,
        "timestamp": datetime.now(UTC).isoformat(),
        "domains": {},
    }
