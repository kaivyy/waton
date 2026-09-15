from __future__ import annotations

import os
from pathlib import Path

from tools.parity.scan_baileys_parity import scan_parity

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WATON_ROOT = os.environ.get("WATON_ROOT", str(ROOT / "waton"))
DEFAULT_BAILEYS_SRC = os.environ.get(
    "BAILEYS_SRC",
    str(ROOT / "repos" / "Baileys" / "src" if (ROOT / "repos" / "Baileys" / "src").exists() else ROOT / "waton"),
)


def test_parity_scan_reports_core_domains() -> None:
    report = scan_parity(
        waton_root=DEFAULT_WATON_ROOT,
        baileys_src=DEFAULT_BAILEYS_SRC,
    )
    assert "messages-recv" in report["domains"]
    assert "messages-send" in report["domains"]
    assert "process-message" in report["domains"]
    assert "connection-core" in report["domains"]
    assert "groups-api" in report["domains"]
    assert "communities-api" in report["domains"]
    assert "newsletter-api" in report["domains"]
    assert "app-state-sync" in report["domains"]
    assert "retry-manager" in report["domains"]
    assert "group-signal" in report["domains"]


def test_parity_scan_includes_metrics() -> None:
    report = scan_parity(
        waton_root=DEFAULT_WATON_ROOT,
        baileys_src=DEFAULT_BAILEYS_SRC,
    )
    recv = report["domains"]["messages-recv"]
    assert recv["status"] in {"missing", "partial", "done"}
    assert recv["waton_lines"] > 0
    assert recv["baileys_lines"] > 0
    assert isinstance(recv["ratio"], float)


def test_parity_scan_includes_baileys_v7_delta_matrix() -> None:
    report = scan_parity(
        waton_root=DEFAULT_WATON_ROOT,
        baileys_src=DEFAULT_BAILEYS_SRC,
    )

    matrix = report["baileys_v7"]
    domains = matrix["domains"]

    assert matrix["reference"] == "baileys-v7-rc11"
    assert "lid-mapping" in domains
    assert "tctoken" in domains
    assert "retry-resend" in domains
    assert "wa-version-drift" in domains
    assert domains["lid-mapping"]["activation_gate"] == "storage-first-shadow-mode"
    assert domains["retry-resend"]["default_behavior"] == "unchanged"
