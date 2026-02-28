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


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _line_count(path: Path) -> int:
    return len(_read_text(path).splitlines())


def _has_stub_marker(path: Path) -> bool:
    text = _read_text(path)
    return any(marker in text for marker in STUB_MARKERS)


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


def scan_parity(waton_root: str, baileys_src: str) -> dict:
    waton = Path(waton_root)
    baileys = Path(baileys_src)

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
        "business-api": _domain_status(
            [waton / "client" / "business.py"],
            [baileys / "Socket" / "business.ts", baileys / "Utils" / "business.ts"],
        ),
        "usync-api": _domain_status(
            [waton / "client" / "usync.py"],
            [baileys / "WAUSync" / "USyncQuery.ts", baileys / "WAUSync" / "Protocols" / "USyncContactProtocol.ts", baileys / "WAUSync" / "Protocols" / "USyncStatusProtocol.ts", baileys / "WAUSync" / "Protocols" / "UsyncLIDProtocol.ts", baileys / "WAUSync" / "Protocols" / "USyncDisappearingModeProtocol.ts"],
        ),
        "mex-api": _domain_status(
            [waton / "client" / "mex.py"],
            [baileys / "Socket" / "mex.ts"],
        ),
        "wam-protocol": _domain_status(
            [waton / "protocol" / "wam.py"],
            [baileys / "WAM" / "encode.ts", baileys / "WAM" / "BinaryInfo.ts"],
        ),
        "connection-core": _domain_status(
            [waton / "client" / "client.py"],
            [baileys / "Socket" / "socket.ts"],
        ),
    }
    return {"domains": domains}


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan parity between Waton and Baileys core domains.")
    parser.add_argument("--waton", required=True, help="Path to waton package root (e.g. .../waton/waton)")
    parser.add_argument("--baileys", required=True, help="Path to baileys src root (e.g. .../Baileys/src)")
    parser.add_argument("--out", help="Optional output JSON path")
    args = parser.parse_args()

    report = scan_parity(args.waton, args.baileys)
    payload = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)


if __name__ == "__main__":
    main()
