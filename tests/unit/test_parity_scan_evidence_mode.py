from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.parity.scan_baileys_parity import scan_parity

if TYPE_CHECKING:
    from pathlib import Path


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _create_minimal_parity_tree(tmp_path: Path) -> tuple[Path, Path]:
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

    return waton_root, baileys_src


@pytest.fixture
def parity_tree(tmp_path: Path) -> tuple[Path, Path]:
    return _create_minimal_parity_tree(tmp_path)


def test_scan_parity_rejects_evidence_without_required_top_level_fields(
    parity_tree: tuple[Path, Path],
) -> None:
    waton_root, baileys_src = parity_tree
    evidence = {
        "domains": {
            "messages-recv": {"replay_pass_rate": 1.0},
        }
    }

    with pytest.raises(ValueError) as exc_info:
        scan_parity(
            waton_root=str(waton_root),
            baileys_src=str(baileys_src),
            evidence=evidence,
        )

    assert str(exc_info.value).startswith("missing required evidence top-level fields")


@pytest.mark.parametrize(
    "evidence",
    [
        {
            "run_id": "",
            "commit_sha": "abc123",
            "timestamp": "2026-03-03T00:00:00+00:00",
            "domains": {},
        },
        {
            "run_id": "r1",
            "commit_sha": "   ",
            "timestamp": "2026-03-03T00:00:00+00:00",
            "domains": {},
        },
        {
            "run_id": "r1",
            "commit_sha": "abc123",
            "timestamp": None,
            "domains": {},
        },
        {
            "run_id": "r1",
            "commit_sha": "abc123",
            "timestamp": "2026-03-03T00:00:00+00:00",
            "domains": [],
        },
    ],
)
def test_scan_parity_rejects_invalid_evidence_top_level_shapes(
    parity_tree: tuple[Path, Path], evidence: dict[str, object]
) -> None:
    waton_root, baileys_src = parity_tree

    with pytest.raises(ValueError, match="invalid evidence top-level field types/shapes"):
        scan_parity(
            waton_root=str(waton_root),
            baileys_src=str(baileys_src),
            evidence=evidence,
        )


def test_scan_parity_accepts_evidence_overlay(parity_tree: tuple[Path, Path]) -> None:
    waton_root, baileys_src = parity_tree
    evidence = {
        "run_id": "r1",
        "commit_sha": "abc123",
        "timestamp": "2026-03-03T00:00:00+00:00",
        "domains": {
            "messages-recv": {"replay_pass_rate": 1.0, "unknown_event_count": 0},
        },
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


def test_scan_parity_preserves_evidence_top_level_metadata(parity_tree: tuple[Path, Path]) -> None:
    waton_root, baileys_src = parity_tree
    evidence = {
        "run_id": "r2",
        "commit_sha": "def456",
        "timestamp": "2026-03-04T00:00:00+00:00",
        "domains": {
            "messages-recv": {"replay_pass_rate": 1.0, "unknown_event_count": 0},
        },
    }

    report = scan_parity(
        waton_root=str(waton_root),
        baileys_src=str(baileys_src),
        evidence=evidence,
    )

    assert report["run_id"] == "r2"
    assert report["commit_sha"] == "def456"
    assert report["timestamp"] == "2026-03-04T00:00:00+00:00"
