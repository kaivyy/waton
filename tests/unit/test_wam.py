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

    assert payload.startswith(b"WAM1")
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
