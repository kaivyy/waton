from __future__ import annotations

from waton.utils.preflight import validate_parity_report


def test_validate_parity_report_fails_when_done_without_evidence() -> None:
    report = {"domains": {"messages-recv": {"status": "done"}}}
    issues = validate_parity_report(report, strict=True)
    assert issues
    assert any("messages-recv" in issue for issue in issues)
    assert any("missing evidence" in issue for issue in issues)
