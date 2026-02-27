"""Shared incoming message content parser.

This module mirrors Baileys' normalize/content-type approach in a lightweight
way by parsing protobuf wire fields directly. It avoids requiring full WAProto
coverage while still exposing richer message metadata.
"""

from __future__ import annotations

import base64
import struct
from typing import Any

from waton.protocol.protobuf import wa_pb2
from waton.protocol.protobuf.wire import _iter_fields

_FUTURE_PROOF_FIELDS = {
    37, 40, 53, 55, 58, 59, 62, 67, 74, 85, 87, 90, 91, 92, 93, 95, 96, 99, 100, 101, 103, 104, 106
}

_POLL_CREATION_FIELDS = (49, 60, 64, 111)


def _decode_utf8(value: bytes | bytearray | memoryview | None) -> str | None:
    if value is None:
        return None
    return bytes(value).decode("utf-8", errors="ignore")


def _field_bytes(payload: bytes, field_number: int) -> bytes | None:
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == field_number and wire_type == 2:
            return bytes(value)
    return None


def _field_strings(payload: bytes, field_number: int) -> list[str]:
    out: list[str] = []
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == field_number and wire_type == 2:
            out.append(bytes(value).decode("utf-8", errors="ignore"))
    return out


def _field_varint(payload: bytes, field_number: int) -> int | None:
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == field_number and wire_type == 0:
            return int(value)
    return None


def _field_bool(payload: bytes, field_number: int) -> bool | None:
    value = _field_varint(payload, field_number)
    if value is None:
        return None
    return bool(value)


def _field_fixed64_double(payload: bytes, field_number: int) -> float | None:
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == field_number and wire_type == 1:
            return float(struct.unpack("<d", bytes(value))[0])
    return None


def _unwrap_future_proof_message(payload: bytes) -> tuple[bytes, list[int]]:
    wrappers: list[int] = []
    current = payload
    for _ in range(8):
        wrapped_payload: bytes | None = None
        wrapped_field: int | None = None
        for field_no, wire_type, value in _iter_fields(current):
            if field_no in _FUTURE_PROOF_FIELDS and wire_type == 2:
                future_payload = bytes(value)
                nested = _field_bytes(future_payload, 1)
                if nested:
                    wrapped_payload = nested
                    wrapped_field = field_no
                    break
        if wrapped_payload is None or wrapped_field is None:
            break
        wrappers.append(wrapped_field)
        current = wrapped_payload
    return current, wrappers


def _extract_context_message_secret_b64(context_payload: bytes | None) -> str | None:
    if context_payload is None:
        return None
    secret = _field_bytes(context_payload, 3)
    if secret is None:
        return None
    return base64.b64encode(secret).decode("ascii")


def _decode_image(payload: bytes) -> dict[str, Any]:
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 2)),
        "caption": _decode_utf8(_field_bytes(payload, 3)),
        "direct_path": _decode_utf8(_field_bytes(payload, 10)),
    }


def _decode_document(payload: bytes) -> dict[str, Any]:
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 2)),
        "title": _decode_utf8(_field_bytes(payload, 3)),
        "file_name": _decode_utf8(_field_bytes(payload, 8)),
        "direct_path": _decode_utf8(_field_bytes(payload, 10)),
        "caption": _decode_utf8(_field_bytes(payload, 20)),
    }


def _decode_audio(payload: bytes) -> dict[str, Any]:
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 2)),
        "seconds": _field_varint(payload, 5),
        "ptt": _field_bool(payload, 6),
        "direct_path": _decode_utf8(_field_bytes(payload, 9)),
    }


def _decode_video(payload: bytes) -> dict[str, Any]:
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 2)),
        "seconds": _field_varint(payload, 5),
        "caption": _decode_utf8(_field_bytes(payload, 7)),
        "height": _field_varint(payload, 9),
        "width": _field_varint(payload, 10),
        "direct_path": _decode_utf8(_field_bytes(payload, 13)),
    }


def _decode_sticker(payload: bytes) -> dict[str, Any]:
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 5)),
        "height": _field_varint(payload, 6),
        "width": _field_varint(payload, 7),
        "direct_path": _decode_utf8(_field_bytes(payload, 8)),
        "is_animated": _field_bool(payload, 13),
    }


def _decode_contact(payload: bytes) -> dict[str, Any]:
    return {
        "display_name": _decode_utf8(_field_bytes(payload, 1)),
        "vcard": _decode_utf8(_field_bytes(payload, 16)),
    }


def _decode_location(payload: bytes) -> dict[str, Any]:
    return {
        "degrees_latitude": _field_fixed64_double(payload, 1),
        "degrees_longitude": _field_fixed64_double(payload, 2),
        "name": _decode_utf8(_field_bytes(payload, 3)),
        "address": _decode_utf8(_field_bytes(payload, 4)),
        "url": _decode_utf8(_field_bytes(payload, 5)),
        "comment": _decode_utf8(_field_bytes(payload, 11)),
    }


def _decode_live_location(payload: bytes) -> dict[str, Any]:
    return {
        "degrees_latitude": _field_fixed64_double(payload, 1),
        "degrees_longitude": _field_fixed64_double(payload, 2),
        "caption": _decode_utf8(_field_bytes(payload, 6)),
        "sequence_number": _field_varint(payload, 7),
    }


def _decode_list_message(payload: bytes) -> dict[str, Any]:
    return {
        "title": _decode_utf8(_field_bytes(payload, 1)),
        "description": _decode_utf8(_field_bytes(payload, 2)),
        "button_text": _decode_utf8(_field_bytes(payload, 3)),
        "footer_text": _decode_utf8(_field_bytes(payload, 7)),
    }


def _decode_buttons_message(payload: bytes) -> dict[str, Any]:
    return {
        "header_text": _decode_utf8(_field_bytes(payload, 1)),
        "content_text": _decode_utf8(_field_bytes(payload, 6)),
        "footer_text": _decode_utf8(_field_bytes(payload, 7)),
    }


def _decode_template_message(payload: bytes) -> dict[str, Any]:
    hydrated = _field_bytes(payload, 2) or _field_bytes(payload, 4)
    hydrated_content = _decode_utf8(_field_bytes(hydrated, 6)) if hydrated else None
    hydrated_footer = _decode_utf8(_field_bytes(hydrated, 7)) if hydrated else None
    return {
        "template_id": _decode_utf8(_field_bytes(payload, 9)),
        "content_text": hydrated_content,
        "footer_text": hydrated_footer,
    }


def _decode_poll_creation(payload: bytes) -> tuple[dict[str, Any], str | None]:
    options: list[str] = []
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == 3 and wire_type == 2:
            option_name = _decode_utf8(_field_bytes(bytes(value), 1))
            if option_name:
                options.append(option_name)
    content = {
        "enc_key_b64": (
            base64.b64encode(_field_bytes(payload, 1)).decode("ascii")
            if _field_bytes(payload, 1) is not None
            else None
        ),
        "name": _decode_utf8(_field_bytes(payload, 2)),
        "options": options,
        "selectable_options_count": _field_varint(payload, 4),
    }
    secret = _extract_context_message_secret_b64(_field_bytes(payload, 5))
    return content, secret


def _decode_event_message(payload: bytes) -> tuple[dict[str, Any], str | None]:
    content = {
        "name": _decode_utf8(_field_bytes(payload, 3)),
        "description": _decode_utf8(_field_bytes(payload, 4)),
        "join_link": _decode_utf8(_field_bytes(payload, 6)),
        "start_time": _field_varint(payload, 7),
        "end_time": _field_varint(payload, 8),
        "is_canceled": _field_bool(payload, 2),
        "extra_guests_allowed": _field_bool(payload, 9),
    }
    location_payload = _field_bytes(payload, 5)
    if location_payload is not None:
        content["location"] = _decode_location(location_payload)
    secret = _extract_context_message_secret_b64(_field_bytes(payload, 1))
    return content, secret


def _decode_newsletter_admin_invite(payload: bytes) -> dict[str, Any]:
    return {
        "newsletter_jid": _decode_utf8(_field_bytes(payload, 1)),
        "newsletter_name": _decode_utf8(_field_bytes(payload, 2)),
        "caption": _decode_utf8(_field_bytes(payload, 4)),
        "invite_expiration": _field_varint(payload, 5),
    }


def _decode_newsletter_follower_invite(payload: bytes) -> dict[str, Any]:
    return {
        "newsletter_jid": _decode_utf8(_field_bytes(payload, 1)),
        "newsletter_name": _decode_utf8(_field_bytes(payload, 2)),
        "caption": _decode_utf8(_field_bytes(payload, 4)),
    }


def parse_message_payload(payload: bytes, *, allow_device_sent: bool = True) -> dict[str, Any]:
    """Parse incoming Message payload into a normalized content summary."""
    summary: dict[str, Any] = {
        "text": None,
        "media_url": None,
        "reaction": None,
        "reaction_target_id": None,
        "destination_jid": None,
        "message_kind": "unknown",
        "content_type": "unknown",
        "content": {},
        "message_secret_b64": None,
        "wrappers": [],
    }
    if not payload:
        return summary

    normalized_payload, wrappers = _unwrap_future_proof_message(payload)
    summary["wrappers"] = wrappers

    message = wa_pb2.Message()
    try:
        message.ParseFromString(normalized_payload)
    except Exception:
        pass

    text = message.conversation or message.extendedTextMessage.text or message.imageMessage.caption or None
    media_url = message.imageMessage.url or None
    reaction = message.reactionMessage.text or None
    reaction_target_id = message.reactionMessage.key.id or None
    destination_jid = message.deviceSentMessage.destinationJid or None

    if reaction:
        summary["message_kind"] = "reaction"
        summary["content_type"] = "reaction"
    elif media_url:
        summary["message_kind"] = "media"
    elif text:
        summary["message_kind"] = "text"
        summary["content_type"] = "text"

    summary["text"] = text
    summary["media_url"] = media_url
    summary["reaction"] = reaction
    summary["reaction_target_id"] = reaction_target_id
    summary["destination_jid"] = destination_jid

    direct_message_secret = _extract_context_message_secret_b64(_field_bytes(normalized_payload, 35))
    if direct_message_secret:
        summary["message_secret_b64"] = direct_message_secret

    if allow_device_sent:
        device_sent_payload = _field_bytes(normalized_payload, 31)
        if device_sent_payload is not None:
            nested_payload = _field_bytes(device_sent_payload, 2)
            nested_destination = _decode_utf8(_field_bytes(device_sent_payload, 1))
            if nested_destination:
                summary["destination_jid"] = nested_destination
            if nested_payload is not None:
                nested = parse_message_payload(nested_payload, allow_device_sent=False)
                if summary["text"] is None:
                    summary["text"] = nested.get("text")
                if summary["media_url"] is None:
                    summary["media_url"] = nested.get("media_url")
                if summary["reaction"] is None:
                    summary["reaction"] = nested.get("reaction")
                if summary["reaction_target_id"] is None:
                    summary["reaction_target_id"] = nested.get("reaction_target_id")
                if summary["content_type"] == "unknown" and isinstance(nested.get("content_type"), str):
                    summary["content_type"] = nested["content_type"]
                if not summary["content"] and isinstance(nested.get("content"), dict):
                    summary["content"] = dict(nested["content"])
                if summary["message_secret_b64"] is None and isinstance(nested.get("message_secret_b64"), str):
                    summary["message_secret_b64"] = nested["message_secret_b64"]
                if summary["message_kind"] == "unknown" and nested.get("message_kind") in {"text", "media", "reaction"}:
                    summary["message_kind"] = "device_sent"

    decoders: list[tuple[int, str, Any]] = [
        (3, "image", _decode_image),
        (7, "document", _decode_document),
        (8, "audio", _decode_audio),
        (9, "video", _decode_video),
        (26, "sticker", _decode_sticker),
        (4, "contact", _decode_contact),
        (5, "location", _decode_location),
        (18, "live_location", _decode_live_location),
        (36, "list", _decode_list_message),
        (42, "buttons", _decode_buttons_message),
        (25, "template", _decode_template_message),
    ]

    if summary["content_type"] == "unknown":
        for field_number, content_type, decoder in decoders:
            content_payload = _field_bytes(normalized_payload, field_number)
            if content_payload is None:
                continue
            content = decoder(content_payload)
            summary["content_type"] = content_type
            summary["content"] = content
            if content_type in {"image", "document", "audio", "video", "sticker"}:
                url = content.get("url")
                if isinstance(url, str) and url:
                    summary["media_url"] = url
                    if summary["message_kind"] == "unknown":
                        summary["message_kind"] = "media"
            caption = content.get("caption")
            if isinstance(caption, str) and caption and summary["text"] is None:
                summary["text"] = caption
                if summary["message_kind"] == "unknown":
                    summary["message_kind"] = "text"
            break

    if summary["content_type"] == "unknown":
        for field_number in _POLL_CREATION_FIELDS:
            poll_payload = _field_bytes(normalized_payload, field_number)
            if poll_payload is None:
                continue
            content, poll_secret = _decode_poll_creation(poll_payload)
            summary["content_type"] = "poll_creation"
            summary["content"] = content
            if poll_secret:
                summary["message_secret_b64"] = poll_secret
            break

    if summary["content_type"] == "unknown":
        event_payload = _field_bytes(normalized_payload, 75)
        if event_payload is not None:
            content, event_secret = _decode_event_message(event_payload)
            summary["content_type"] = "event"
            summary["content"] = content
            if event_secret:
                summary["message_secret_b64"] = event_secret

    if summary["content_type"] == "unknown":
        admin_invite_payload = _field_bytes(normalized_payload, 78)
        if admin_invite_payload is not None:
            summary["content_type"] = "newsletter_admin_invite"
            summary["content"] = _decode_newsletter_admin_invite(admin_invite_payload)

    if summary["content_type"] == "unknown":
        follower_invite_payload = _field_bytes(normalized_payload, 113)
        if follower_invite_payload is not None:
            summary["content_type"] = "newsletter_follower_invite"
            summary["content"] = _decode_newsletter_follower_invite(follower_invite_payload)

    # For poll/event payloads with no text/media/reaction, map kind to content type.
    if summary["message_kind"] == "unknown" and summary["content_type"] != "unknown":
        summary["message_kind"] = summary["content_type"]

    # Preserve text fallbacks for captions inside known media payloads.
    if summary["text"] is None and isinstance(summary["content"], dict):
        for key in ("caption", "title", "content_text", "name"):
            candidate = summary["content"].get(key)
            if isinstance(candidate, str) and candidate:
                summary["text"] = candidate
                if summary["message_kind"] == "unknown":
                    summary["message_kind"] = "text"
                break

    return summary

