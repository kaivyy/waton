from waton.protocol.wam import encode_wam_event


def test_encode_wam_event_includes_header_and_payload_fields() -> None:
    payload = encode_wam_event(
        event_name="message_send",
        event_code=1001,
        fields={
            "chat_type": "private",
            "retry_count": 2,
            "is_business": False,
        },
    )

    assert payload.startswith(b"WAM2")
    assert b"event:message_send" in payload
    assert b"code:1001" in payload
    assert b"chat_type=s:private" in payload
    assert b"retry_count=i:2" in payload
    assert b"is_business=b:0" in payload


def test_encode_wam_event_is_deterministic_for_same_input() -> None:
    a = encode_wam_event(
        event_name="message_send",
        event_code=1001,
        fields={"retry_count": 2, "chat_type": "private"},
    )
    b = encode_wam_event(
        event_name="message_send",
        event_code=1001,
        fields={"retry_count": 2, "chat_type": "private"},
    )

    assert a == b


def test_encode_wam_event_supports_extended_scalar_types() -> None:
    payload = encode_wam_event(
        event_name="delivery_telemetry",
        event_code=1200,
        fields={
            "latency_ms": 12.5,
            "network": "wifi",
            "is_retry": True,
            "attempt": 3,
            "region": "apac",
            "app_build": 20260228,
        },
    )

    assert b"latency_ms=f:12.5" in payload
    assert b"network=s:wifi" in payload
    assert b"is_retry=b:1" in payload
    assert b"attempt=i:3" in payload
    assert b"region=s:apac" in payload
    assert b"app_build=i:20260228" in payload


def test_encode_wam_event_rejects_empty_name() -> None:
    try:
        encode_wam_event(event_name="", event_code=1, fields={})
    except ValueError as exc:
        assert "event_name" in str(exc)
    else:
        raise AssertionError("expected ValueError for empty event_name")


def test_encode_wam_event_accepts_nested_payloads() -> None:
    payload = encode_wam_event(
        event_name="message_pipeline",
        event_code=2002,
        fields={
            "meta": {"stage": "decrypt", "ok": True},
            "retry_chain": [1, 2, 3],
        },
    )

    assert b"meta=j:{\"ok\":true,\"stage\":\"decrypt\"}" in payload
    assert b"retry_chain=j:[1,2,3]" in payload


def test_encode_wam_event_uses_versioned_header_v2() -> None:
    payload = encode_wam_event(event_name="bootstrap", event_code=10, fields={})
    assert payload.startswith(b"WAM2")
