from __future__ import annotations

from waton.protocol.protobuf.wire import (
    encode_bool,
    encode_len_delimited,
    encode_string,
    encode_varint_field,
)
from waton.utils.message_content import parse_message_payload


def test_parse_message_payload_extracts_image_media_key_b64() -> None:
    media_key = bytes(range(32))
    image_payload = b"".join(
        (
            encode_string(1, "https://media.local/image"),
            encode_string(2, "image/jpeg"),
            encode_len_delimited(8, media_key),
        )
    )
    payload = encode_len_delimited(3, image_payload)

    summary = parse_message_payload(payload)

    assert summary["content_type"] == "image"
    content = summary["content"]
    assert isinstance(content, dict)
    assert content.get("url") == "https://media.local/image"
    assert content.get("mimetype") == "image/jpeg"
    assert content.get("media_key_b64") is not None


def test_parse_message_payload_extracts_document_media_key_b64() -> None:
    media_key = b"k" * 32
    document_payload = b"".join(
        (
            encode_string(1, "https://media.local/document"),
            encode_string(2, "application/pdf"),
            encode_len_delimited(7, media_key),
        )
    )
    payload = encode_len_delimited(7, document_payload)

    summary = parse_message_payload(payload)

    assert summary["content_type"] == "document"
    content = summary["content"]
    assert isinstance(content, dict)
    assert content.get("media_key_b64") is not None


def test_parse_message_payload_decodes_pin_in_chat() -> None:
    key_payload = b"".join(
        (
            encode_string(1, "123456789@s.whatsapp.net"),
            encode_bool(2, False),
            encode_string(3, "MSG12345"),
        )
    )
    pin_payload = b"".join(
        (
            encode_len_delimited(1, key_payload),
            encode_varint_field(2, 1),  # PIN_FOR_ALL
            encode_varint_field(3, 1700000000000),
        )
    )
    payload = encode_len_delimited(63, pin_payload)

    summary = parse_message_payload(payload)

    assert summary["content_type"] == "pin_in_chat"
    assert summary["message_kind"] == "pin_in_chat"
    content = summary["content"]
    assert isinstance(content, dict)
    assert content.get("type") == 1
    assert content.get("sender_timestamp_ms") == 1700000000000
    assert content["key"]["id"] == "MSG12345"
    assert content["key"]["remote_jid"] == "123456789@s.whatsapp.net"


def test_parse_message_payload_decodes_ptv() -> None:
    media_key = b"v" * 32
    video_payload = b"".join(
        (
            encode_string(1, "https://media.local/ptv.mp4"),
            encode_string(2, "video/mp4"),
            encode_varint_field(5, 12),
            encode_len_delimited(6, media_key),
        )
    )
    payload = encode_len_delimited(66, video_payload)

    summary = parse_message_payload(payload)

    assert summary["content_type"] == "ptv"
    assert summary["message_kind"] == "media"
    content = summary["content"]
    assert isinstance(content, dict)
    assert content.get("ptv") is True
    assert content.get("seconds") == 12
    assert content.get("media_key_b64") is not None


def test_parse_message_payload_decodes_group_invite() -> None:
    invite_payload = b"".join(
        (
            encode_string(1, "123456@g.us"),
            encode_string(2, "INVITECODE123"),
            encode_varint_field(3, 1700000000),
            encode_string(4, "My Test Group"),
            encode_string(6, "Join our cool group"),
        )
    )
    payload = encode_len_delimited(28, invite_payload)

    summary = parse_message_payload(payload)

    assert summary["content_type"] == "group_invite"
    content = summary["content"]
    assert isinstance(content, dict)
    assert content.get("group_jid") == "123456@g.us"
    assert content.get("invite_code") == "INVITECODE123"
    assert content.get("group_name") == "My Test Group"
    assert content.get("caption") == "Join our cool group"


def test_parse_message_payload_decodes_payment_invite() -> None:
    payment_payload = b"".join(
        (
            encode_varint_field(1, 3),  # UPI
            encode_varint_field(2, 1700000000),
        )
    )
    payload = encode_len_delimited(44, payment_payload)

    summary = parse_message_payload(payload)

    assert summary["content_type"] == "payment_invite"
    content = summary["content"]
    assert isinstance(content, dict)
    assert content.get("service_type") == 3
    assert content.get("expiry_timestamp") == 1700000000


def test_parse_message_payload_extracts_context_info_and_quoted_message() -> None:
    quoted_proto = encode_string(1, "Original message")
    context_info_payload = b"".join(
        (
            encode_string(1, "STZ-1234"),
            encode_string(2, "alice@s.whatsapp.net"),
            encode_len_delimited(3, quoted_proto),
            encode_string(4, "chat@g.us"),
            encode_string(15, "bob@s.whatsapp.net"),
            encode_string(15, "charlie@s.whatsapp.net"),
        )
    )
    ext_payload = b"".join(
        (
            encode_string(1, "Reply message"),
            encode_len_delimited(17, context_info_payload),
        )
    )
    payload = encode_len_delimited(6, ext_payload)

    summary = parse_message_payload(payload)

    assert summary["text"] == "Reply message"
    assert summary["context_info"] is not None
    ctx = summary["context_info"]
    assert ctx["stanza_id"] == "STZ-1234"
    assert ctx["participant"] == "alice@s.whatsapp.net"
    assert ctx["remote_jid"] == "chat@g.us"
    assert ctx["mentioned_jid"] == ["bob@s.whatsapp.net", "charlie@s.whatsapp.net"]
    assert ctx["quoted_message"]["text"] == "Original message"


def test_parse_message_payload_decodes_reaction_with_participant_and_unreact() -> None:
    # 1. Reaction addition
    key_payload = b"".join(
        (
            encode_string(1, "group@g.us"),
            encode_bool(2, False),
            encode_string(3, "MSG-999"),
            encode_string(4, "author@s.whatsapp.net"),
        )
    )
    react_payload = b"".join(
        (
            encode_len_delimited(1, key_payload),
            encode_string(2, "🎉"),
            encode_varint_field(4, 1700000000123),
        )
    )
    payload1 = encode_len_delimited(46, react_payload)

    summary1 = parse_message_payload(payload1)
    assert summary1["message_kind"] == "reaction"
    assert summary1["content_type"] == "reaction"
    assert summary1["reaction"] == "🎉"
    assert summary1["reaction_target_id"] == "MSG-999"
    assert summary1["reaction_target_participant"] == "author@s.whatsapp.net"
    assert summary1["is_reaction_removal"] is False
    assert summary1["content"]["sender_timestamp_ms"] == 1700000000123

    # 2. Reaction removal (unreact)
    unreact_payload = b"".join(
        (
            encode_len_delimited(1, key_payload),
            encode_string(2, ""),
            encode_varint_field(4, 1700000000456),
        )
    )
    payload2 = encode_len_delimited(46, unreact_payload)

    summary2 = parse_message_payload(payload2)
    assert summary2["message_kind"] == "reaction"
    assert summary2["content_type"] == "reaction"
    assert summary2["reaction"] is None
    assert summary2["reaction_target_id"] == "MSG-999"
    assert summary2["reaction_target_participant"] == "author@s.whatsapp.net"
    assert summary2["is_reaction_removal"] is True

