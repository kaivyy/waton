from tools.parity.evidence import build_empty_evidence


def test_evidence_schema_has_required_fields() -> None:
    evidence = build_empty_evidence(run_id="r1", commit_sha="abc123")
    assert "run_id" in evidence
    assert "commit_sha" in evidence
    assert "domains" in evidence
    assert "timestamp" in evidence
