from __future__ import annotations

from tools.parity.scan_baileys_parity import scan_parity


def test_parity_scan_reports_core_domains() -> None:
    report = scan_parity(
        waton_root=r"C:\Users\Arvy Kairi\Desktop\whatsapp\waton\waton",
        baileys_src=r"C:\Users\Arvy Kairi\Desktop\whatsapp\Baileys\src",
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
        waton_root=r"C:\Users\Arvy Kairi\Desktop\whatsapp\waton\waton",
        baileys_src=r"C:\Users\Arvy Kairi\Desktop\whatsapp\Baileys\src",
    )
    recv = report["domains"]["messages-recv"]
    assert recv["status"] in {"missing", "partial", "done"}
    assert recv["waton_lines"] > 0
    assert recv["baileys_lines"] > 0
    assert isinstance(recv["ratio"], float)
