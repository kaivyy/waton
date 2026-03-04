from __future__ import annotations

from waton.protocol.protobuf.wire import encode_len_delimited, encode_string
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
