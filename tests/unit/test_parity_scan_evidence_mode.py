from __future__ import annotations

from tools.parity.scan_baileys_parity import scan_parity


def test_scan_parity_accepts_evidence_overlay() -> None:
    evidence = {
        "domains": {
            "messages-recv": {"replay_pass_rate": 1.0, "unknown_event_count": 0},
        }
    }

    report = scan_parity(
        waton_root=r"C:\Users\Arvy Kairi\Desktop\whatsapp\waton\waton",
        baileys_src=r"C:\Users\Arvy Kairi\Desktop\whatsapp\Baileys\src",
        evidence=evidence,
    )

    assert report["domains"]["messages-recv"]["evidence"] == {
        "replay_pass_rate": 1.0,
        "unknown_event_count": 0,
    }
    assert report["domains"]["messages-send"]["evidence"] == {}
