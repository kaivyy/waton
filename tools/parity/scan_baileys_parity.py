from __future__ import annotations

import argparse
import json
from pathlib import Path

STUB_MARKERS = (
    "stub_",
    "stub",
    "NotImplemented",
    "TODO",
    "FIXME",
)


BAILEYS_V7_REFERENCE = "baileys-v7-rc11"

BAILEYS_V7_DOMAINS: dict[str, dict[str, object]] = {
    "lid-mapping": {
        "status": "partial",
        "risk": "high",
        "default_behavior": "unchanged",
        "activation_gate": "storage-first-shadow-mode",
        "waton_files": ["waton/core/jid.py", "waton/protocol/signal_repo.py"],
        "baileys_files": ["src/Signal/lid-mapping.ts", "src/Utils/sync-action-utils.ts"],
    },
    "tctoken": {
        "status": "planned",
        "risk": "high",
        "default_behavior": "unchanged",
        "activation_gate": "feature-flag-and-replay-evidence",
        "waton_files": ["waton/client/retry_manager.py"],
        "baileys_files": ["src/Utils/tc-token-utils.ts"],
    },
    "retry-resend": {
        "status": "partial",
        "risk": "high",
        "default_behavior": "unchanged",
        "activation_gate": "feature-flag-and-differential-fixtures",
        "waton_files": ["waton/client/retry_manager.py", "waton/client/messages_recv.py"],
        "baileys_files": ["src/Utils/message-retry-manager.ts", "src/Socket/messages-recv.ts"],
    },
    "app-state-resilience": {
        "status": "partial",
        "risk": "medium",
        "default_behavior": "unchanged",
        "activation_gate": "shadow-mode-error-classification",
        "waton_files": ["waton/protocol/app_state.py", "waton/utils/chat_utils.py"],
        "baileys_files": ["src/Utils/chat-utils.ts", "src/Utils/process-message.ts"],
    },
    "offline-node-batching": {
        "status": "partial",
        "risk": "medium",
        "default_behavior": "unchanged",
        "activation_gate": "batching-benchmarks-and-event-order-fixtures",
        "waton_files": ["waton/client/event_pipeline.py", "waton/client/client.py"],
        "baileys_files": ["src/Utils/offline-node-processor.ts"],
    },
    "send-media-robustness": {
        "status": "partial",
        "risk": "medium",
        "default_behavior": "unchanged",
        "activation_gate": "per-recipient-diagnostics-feature-flag",
        "waton_files": ["waton/client/messages.py", "waton/client/media.py"],
        "baileys_files": ["src/Socket/messages-send.ts", "src/Utils/messages-media.ts"],
    },
    "notification-surface": {
        "status": "partial",
        "risk": "medium",
        "default_behavior": "unchanged",
        "activation_gate": "optional-event-fields-only",
        "waton_files": ["waton/client/messages_recv.py", "waton/core/events.py"],
        "baileys_files": ["src/Socket/messages-recv.ts", "src/Types/Events.ts"],
    },
    "wa-version-drift": {
        "status": "planned",
        "risk": "low",
        "default_behavior": "unchanged",
        "activation_gate": "preflight-report-only",
        "waton_files": ["waton/defaults/config.py"],
        "baileys_files": ["src/Defaults/baileys-version.json"],
    },
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _line_count(path: Path) -> int:
    return len(_read_text(path).splitlines())


def _has_stub_marker(path: Path) -> bool:
    text = _read_text(path)
    return any(marker in text for marker in STUB_MARKERS)


def _baileys_v7_matrix() -> dict[str, object]:
    return {
        "reference": BAILEYS_V7_REFERENCE,
        "compatibility_policy": "additive-first-defaults-unchanged",
        "domains": {domain: dict(payload) for domain, payload in BAILEYS_V7_DOMAINS.items()},
    }


def _domain_status(
    waton_paths: list[Path],
    baileys_paths: list[Path],
) -> dict[str, object]:
    if any(not p.exists() for p in waton_paths) or any(not p.exists() for p in baileys_paths):
        return {"status": "missing", "ratio": 0.0, "waton_lines": 0, "baileys_lines": 0}

    waton_lines = sum(_line_count(p) for p in waton_paths)
    baileys_lines = sum(_line_count(p) for p in baileys_paths)
    ratio = (float(waton_lines) / float(baileys_lines)) if baileys_lines else 1.0
    has_stub = any(_has_stub_marker(p) for p in waton_paths)

    status = "partial" if has_stub or ratio < 0.80 else "done"

    return {
        "status": status,
        "ratio": round(ratio, 4),
        "waton_lines": waton_lines,
        "baileys_lines": baileys_lines,
    }


def _validate_evidence_top_level(evidence: dict[str, object]) -> None:
    required_fields = ("run_id", "commit_sha", "timestamp", "domains")
    missing_fields = [field for field in required_fields if field not in evidence]
    if missing_fields:
        raise ValueError("missing required evidence top-level fields: " + ", ".join(missing_fields))

    invalid_fields: list[str] = []
    for field in ("run_id", "commit_sha", "timestamp"):
        value = evidence.get(field)
        if not isinstance(value, str) or not value.strip():
            invalid_fields.append(field)

    if not isinstance(evidence.get("domains"), dict):
        invalid_fields.append("domains")

    if invalid_fields:
        raise ValueError("invalid evidence top-level field types/shapes: " + ", ".join(invalid_fields))


def _evidence_passes_strict_gate(evidence: dict[str, object]) -> bool:
    replay = evidence.get("replay_pass_rate")
    drift = evidence.get("drift_count")
    wire_artifact = evidence.get("wire_diff_artifact")
    behavior_artifact = evidence.get("behavior_diff_artifact")

    return (
        not isinstance(replay, bool)
        and isinstance(replay, (int, float))
        and replay >= 0.995
        and not isinstance(drift, bool)
        and isinstance(drift, int)
        and drift == 0
        and isinstance(wire_artifact, str)
        and bool(wire_artifact.strip())
        and isinstance(behavior_artifact, str)
        and bool(behavior_artifact.strip())
    )


def scan_parity(waton_root: str, baileys_src: str, evidence: dict | None = None) -> dict:
    waton = Path(waton_root)
    baileys = Path(baileys_src)

    if evidence is not None:
        _validate_evidence_top_level(evidence)

    domains = {
        "messages-recv": _domain_status(
            [waton / "client" / "messages_recv.py", waton / "utils" / "message_content.py"],
            [baileys / "Socket" / "messages-recv.ts"],
        ),
        "app-state-sync": _domain_status(
            [waton / "protocol" / "app_state.py", waton / "utils" / "lt_hash.py"],
            [baileys / "Utils" / "sync-action-utils.ts", baileys / "Utils" / "lt-hash.ts"],
        ),
        "retry-manager": _domain_status(
            [waton / "client" / "retry_manager.py"],
            [baileys / "Utils" / "message-retry-manager.ts"],
        ),
        "group-signal": _domain_status(
            [waton / "protocol" / "group_cipher.py"],
            [baileys / "Signal" / "Group" / "group_cipher.ts"],
        ),
        "messages-send": _domain_status(
            [waton / "client" / "messages.py"],
            [baileys / "Socket" / "messages-send.ts"],
        ),
        "process-message": _domain_status(
            [waton / "utils" / "process_message.py", waton / "utils" / "message_content.py"],
            [baileys / "Utils" / "process-message.ts"],
        ),
        "groups-api": _domain_status(
            [waton / "client" / "groups.py"],
            [baileys / "Socket" / "groups.ts"],
        ),
        "communities-api": _domain_status(
            [waton / "client" / "communities.py"],
            [baileys / "Socket" / "communities.ts"],
        ),
        "newsletter-api": _domain_status(
            [waton / "client" / "newsletter.py"],
            [baileys / "Socket" / "newsletter.ts"],
        ),
        "connection-core": _domain_status(
            [waton / "client" / "client.py"],
            [baileys / "Socket" / "socket.ts"],
        ),
    }

    report: dict[str, object] = {"domains": domains, "baileys_v7": _baileys_v7_matrix()}

    if evidence and isinstance(evidence.get("domains"), dict):
        report["run_id"] = evidence["run_id"]
        report["commit_sha"] = evidence["commit_sha"]
        report["timestamp"] = evidence["timestamp"]
        for domain, payload in report["domains"].items():
            ev = evidence["domains"].get(domain, {})
            payload["evidence"] = ev if isinstance(ev, dict) else {}
            if isinstance(ev, dict) and _evidence_passes_strict_gate(ev):
                payload["static_status"] = payload.get("status")
                payload["status"] = "done"

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan parity between Waton and Baileys core domains.")
    parser.add_argument("--waton", required=True, help="Path to waton package root (e.g. .../waton/waton)")
    parser.add_argument("--baileys", required=True, help="Path to baileys src root (e.g. .../Baileys/src)")
    parser.add_argument("--out", help="Optional output JSON path")
    parser.add_argument("--evidence", help="Optional parity evidence JSON path")
    args = parser.parse_args()

    evidence = None
    if args.evidence:
        evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))

    report = scan_parity(args.waton, args.baileys, evidence=evidence)
    payload = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)


if __name__ == "__main__":
    main()
