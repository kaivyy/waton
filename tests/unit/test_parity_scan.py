from tools.parity.scan_baileys_parity import scan_parity

def test_parity_scan_reports_core_domains() -> None:
    report = scan_parity(
        waton_root=r"C:\Users\Arvy Kairi\Desktop\whatsapp\waton\waton",
        baileys_src=r"C:\Users\Arvy Kairi\Desktop\whatsapp\Baileys\src",
    )
    assert "messages-recv" in report["domains"]
    assert "app-state-sync" in report["domains"]
    assert "retry-manager" in report["domains"]
