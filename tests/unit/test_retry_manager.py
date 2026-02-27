from waton.client.retry_manager import RetryManager, RetryReason


def test_retry_manager_avoids_duplicate_send() -> None:
    mgr = RetryManager(max_attempts=3)
    assert mgr.should_send("msg-1") is True
    assert mgr.should_send("msg-1") is False


def test_retry_manager_respects_max_attempts() -> None:
    mgr = RetryManager(max_attempts=2)
    assert mgr.register_retry("msg-1") == 1
    assert mgr.register_retry("msg-1") == 2
    assert mgr.register_retry("msg-1") == 3
    assert mgr.should_retry("msg-1") is False


def test_retry_manager_tracks_ack_and_blocks_more_retries() -> None:
    mgr = RetryManager(max_attempts=5)
    assert mgr.register_retry("msg-1") == 1
    assert mgr.should_retry("msg-1") is True
    mgr.mark_retry_acked("msg-1")
    assert mgr.should_retry("msg-1") is False


def test_retry_manager_force_send_bypasses_dedup() -> None:
    mgr = RetryManager(max_attempts=3)
    assert mgr.should_send("msg-1") is True
    assert mgr.should_send("msg-1") is False
    assert mgr.should_send("msg-1", force=True) is True


def test_retry_manager_snapshot_and_clear_stale() -> None:
    mgr = RetryManager(max_attempts=3)
    mgr.register_retry("msg-1", error="decrypt", timestamp=100)
    mgr.register_retry("msg-2", error="network", timestamp=200)
    snap = mgr.snapshot()
    assert snap["msg-1"]["last_error"] == "decrypt"
    assert snap["msg-2"]["retry_count"] == 1

    removed = mgr.clear_stale(max_age_seconds=50, now_ts=180)
    assert removed == 1
    assert "msg-1" not in mgr.snapshot()
    assert "msg-2" in mgr.snapshot()


def test_retry_manager_clear_removes_entry() -> None:
    mgr = RetryManager(max_attempts=3)
    mgr.register_retry("msg-1", timestamp=100)
    assert "msg-1" in mgr.snapshot()
    mgr.clear("msg-1")
    assert "msg-1" not in mgr.snapshot()


def test_retry_manager_parse_retry_error_code_and_mac_detection() -> None:
    mgr = RetryManager(max_attempts=3)
    assert mgr.parse_retry_error_code("4") == RetryReason.SignalErrorInvalidMessage
    assert mgr.parse_retry_error_code("7") == RetryReason.SignalErrorBadMac
    assert mgr.parse_retry_error_code("999") == RetryReason.UnknownError
    assert mgr.parse_retry_error_code("nan") is None
    assert mgr.parse_retry_error_code(None) is None
    assert mgr.is_mac_error(RetryReason.SignalErrorInvalidMessage) is True
    assert mgr.is_mac_error(RetryReason.SignalErrorBadMac) is True
    assert mgr.is_mac_error(RetryReason.UnknownError) is False
    assert mgr.is_mac_error(None) is False


def test_retry_manager_should_recreate_session_logic() -> None:
    mgr = RetryManager(max_attempts=3)

    no_session = mgr.should_recreate_session("123@s.whatsapp.net", has_session=False, now_ms=1_000)
    assert no_session["recreate"] is True

    mac_error = mgr.should_recreate_session(
        "123@s.whatsapp.net",
        has_session=True,
        error_code=RetryReason.SignalErrorBadMac,
        now_ms=2_000,
    )
    assert mac_error["recreate"] is True

    recent_recreate = mgr.should_recreate_session("123@s.whatsapp.net", has_session=True, now_ms=2_100)
    assert recent_recreate["recreate"] is False

    timed_out = mgr.should_recreate_session("123@s.whatsapp.net", has_session=True, now_ms=2_000 + 3_700_000)
    assert timed_out["recreate"] is True


def test_retry_manager_statistics_and_recent_message_lifecycle() -> None:
    mgr = RetryManager(max_attempts=3, max_recent_messages=2)
    mgr.add_recent_message("123@s.whatsapp.net", "m1", {"id": "m1"}, timestamp_ms=100)
    mgr.add_recent_message("123@s.whatsapp.net", "m2", {"id": "m2"}, timestamp_ms=200)
    mgr.add_recent_message("123@s.whatsapp.net", "m3", {"id": "m3"}, timestamp_ms=300)

    assert mgr.get_recent_message("123@s.whatsapp.net", "m1") is None
    recent = mgr.get_recent_message_by_id("m3")
    assert recent is not None
    assert recent["message"]["id"] == "m3"

    mgr.increment_retry_count("m3")
    mgr.mark_retry_success("m3")
    stats = mgr.get_statistics()
    assert stats["totalRetries"] == 1
    assert stats["successfulRetries"] == 1
    assert mgr.get_recent_message_by_id("m3") is None

    mgr.increment_retry_count("m4")
    mgr.mark_retry_failed("m4")
    stats = mgr.get_statistics()
    assert stats["failedRetries"] == 1
