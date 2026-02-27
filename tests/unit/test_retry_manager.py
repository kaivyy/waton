from waton.client.retry_manager import RetryManager

def test_retry_manager_avoids_duplicate_send() -> None:
    mgr = RetryManager(max_attempts=3)
    assert mgr.should_send("msg-1") is True
    assert mgr.should_send("msg-1") is False
