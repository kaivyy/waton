from __future__ import annotations

from pathlib import Path

from tools.parity.scan_baileys_parity import scan_parity


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_scan_parity_accepts_evidence_overlay(tmp_path: Path) -> None:
    waton_root = tmp_path / "waton"
    baileys_src = tmp_path / "baileys" / "src"

    # Minimal files required by scanner domain mapping.
    _write_file(waton_root / "client" / "messages_recv.py", "print('ok')\n")
    _write_file(waton_root / "utils" / "message_content.py", "print('ok')\n")
    _write_file(waton_root / "protocol" / "app_state.py", "print('ok')\n")
    _write_file(waton_root / "utils" / "lt_hash.py", "print('ok')\n")
    _write_file(waton_root / "client" / "retry_manager.py", "print('ok')\n")
    _write_file(waton_root / "protocol" / "group_cipher.py", "print('ok')\n")
    _write_file(waton_root / "client" / "messages.py", "print('ok')\n")
    _write_file(waton_root / "utils" / "process_message.py", "print('ok')\n")
    _write_file(waton_root / "client" / "groups.py", "print('ok')\n")
    _write_file(waton_root / "client" / "communities.py", "print('ok')\n")
    _write_file(waton_root / "client" / "newsletter.py", "print('ok')\n")
    _write_file(waton_root / "client" / "client.py", "print('ok')\n")

    _write_file(baileys_src / "Socket" / "messages-recv.ts", "export {}\n")
    _write_file(baileys_src / "Utils" / "sync-action-utils.ts", "export {}\n")
    _write_file(baileys_src / "Utils" / "lt-hash.ts", "export {}\n")
    _write_file(baileys_src / "Utils" / "message-retry-manager.ts", "export {}\n")
    _write_file(baileys_src / "Signal" / "Group" / "group_cipher.ts", "export {}\n")
    _write_file(baileys_src / "Socket" / "messages-send.ts", "export {}\n")
    _write_file(baileys_src / "Utils" / "process-message.ts", "export {}\n")
    _write_file(baileys_src / "Socket" / "groups.ts", "export {}\n")
    _write_file(baileys_src / "Socket" / "communities.ts", "export {}\n")
    _write_file(baileys_src / "Socket" / "newsletter.ts", "export {}\n")
    _write_file(baileys_src / "Socket" / "socket.ts", "export {}\n")

    evidence = {
        "domains": {
            "messages-recv": {"replay_pass_rate": 1.0, "unknown_event_count": 0},
        }
    }

    report = scan_parity(
        waton_root=str(waton_root),
        baileys_src=str(baileys_src),
        evidence=evidence,
    )

    assert report["domains"]["messages-recv"]["evidence"] == {
        "replay_pass_rate": 1.0,
        "unknown_event_count": 0,
    }
    assert report["domains"]["messages-send"]["evidence"] == {}
