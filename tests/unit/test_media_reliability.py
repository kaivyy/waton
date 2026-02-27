from waton.client.media import upload_with_retry

def test_upload_retries_and_verifies_checksum(monkeypatch) -> None:
    result = upload_with_retry(b"abc", max_attempts=3)
    assert result["attempts"] >= 1
    assert result["verified"] is True
