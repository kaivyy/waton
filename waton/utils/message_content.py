"""Shared incoming message content parser.

This module mirrors WhatsApp-Web style normalize/content-type handling in a lightweight
way by parsing protobuf wire fields directly. It avoids requiring full WAProto
coverage while still exposing richer message metadata.
"""

from __future__ import annotations

import base64
import contextlib
import struct
from typing import Any, cast

from waton.protocol.protobuf import wa_pb2
from waton.protocol.protobuf.wire import iter_fields

_FUTURE_PROOF_FIELDS = {
    37, 40, 53, 55, 58, 59, 62, 67, 74, 85, 87, 90, 91, 92, 93, 95, 96, 99, 100, 101, 103, 104, 106
}

_POLL_CREATION_FIELDS = (49, 60, 64, 93, 111)


def _decode_utf8(value: bytes | bytearray | memoryview | None) -> str | None:
    if value is None:
        return None
    return bytes(value).decode("utf-8", errors="ignore")


def _field_bytes(payload: bytes, field_number: int) -> bytes | None:
    for field_no, wire_type, value in iter_fields(payload):
        if field_no == field_number and wire_type == 2:
            return bytes(value)
    return None


def _field_varint(payload: bytes, field_number: int) -> int | None:
    for field_no, wire_type, value in iter_fields(payload):
        if field_no == field_number and wire_type == 0:
            return int(value)
    return None


def _field_bool(payload: bytes, field_number: int) -> bool | None:
    value = _field_varint(payload, field_number)
    if value is None:
        return None
    return bool(value)


def _field_fixed64_double(payload: bytes, field_number: int) -> float | None:
    for field_no, wire_type, value in iter_fields(payload):
        if field_no == field_number and wire_type == 1:
            return float(struct.unpack("<d", bytes(value))[0])
    return None


def _unwrap_future_proof_message(payload: bytes) -> tuple[bytes, list[int]]:
    wrappers: list[int] = []
    current = payload
    for _ in range(8):
        wrapped_payload: bytes | None = None
        wrapped_field: int | None = None
        for field_no, wire_type, value in iter_fields(current):
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
    media_key = _field_bytes(payload, 8)
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 2)),
        "caption": _decode_utf8(_field_bytes(payload, 3)),
        "direct_path": _decode_utf8(_field_bytes(payload, 10)),
        "media_key_b64": base64.b64encode(media_key).decode("ascii") if media_key is not None else None,
    }


def _decode_document(payload: bytes) -> dict[str, Any]:
    media_key = _field_bytes(payload, 7)
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 2)),
        "title": _decode_utf8(_field_bytes(payload, 3)),
        "file_name": _decode_utf8(_field_bytes(payload, 8)),
        "direct_path": _decode_utf8(_field_bytes(payload, 10)),
        "caption": _decode_utf8(_field_bytes(payload, 20)),
        "media_key_b64": base64.b64encode(media_key).decode("ascii") if media_key is not None else None,
    }


def _decode_audio(payload: bytes) -> dict[str, Any]:
    media_key = _field_bytes(payload, 7)
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 2)),
        "seconds": _field_varint(payload, 5),
        "ptt": _field_bool(payload, 6),
        "direct_path": _decode_utf8(_field_bytes(payload, 9)),
        "media_key_b64": base64.b64encode(media_key).decode("ascii") if media_key is not None else None,
    }


def _decode_video(payload: bytes) -> dict[str, Any]:
    media_key = _field_bytes(payload, 6)
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 2)),
        "seconds": _field_varint(payload, 5),
        "caption": _decode_utf8(_field_bytes(payload, 7)),
        "height": _field_varint(payload, 9),
        "width": _field_varint(payload, 10),
        "direct_path": _decode_utf8(_field_bytes(payload, 13)),
        "media_key_b64": base64.b64encode(media_key).decode("ascii") if media_key is not None else None,
    }


def _decode_sticker(payload: bytes) -> dict[str, Any]:
    media_key = _field_bytes(payload, 4)
    return {
        "url": _decode_utf8(_field_bytes(payload, 1)),
        "mimetype": _decode_utf8(_field_bytes(payload, 5)),
        "height": _field_varint(payload, 6),
        "width": _field_varint(payload, 7),
        "direct_path": _decode_utf8(_field_bytes(payload, 8)),
        "is_animated": _field_bool(payload, 13),
        "media_key_b64": base64.b64encode(media_key).decode("ascii") if media_key is not None else None,
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
    enc_key = _field_bytes(payload, 1)
    for field_no, wire_type, value in iter_fields(payload):
        if field_no == 3 and wire_type == 2:
            option_name = _decode_utf8(_field_bytes(bytes(value), 1))
            if option_name:
                options.append(option_name)
    content = {
        "enc_key_b64": (
            base64.b64encode(enc_key).decode("ascii") if enc_key is not None else None
        ),
        "name": _decode_utf8(_field_bytes(payload, 2)),
        "options": options,
        "selectable_options_count": _field_varint(payload, 4),
    }
    context_secret = _extract_context_message_secret_b64(_field_bytes(payload, 5))
    secret = context_secret or (base64.b64encode(enc_key).decode("ascii") if enc_key is not None else None)
    return content, secret



def _decode_event_message(payload: bytes) -> tuple[dict[str, Any], str | None]:
    content: dict[str, Any] = {
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


def _decode_sender_key_distribution(payload: bytes) -> dict[str, Any]:
    return {
        "group_id": _decode_utf8(_field_bytes(payload, 1)),
        "axolotl_sender_key_distribution_message": _field_bytes(payload, 2),
    }


def _decode_group_invite(payload: bytes) -> dict[str, Any]:
    return {
        "group_jid": _decode_utf8(_field_bytes(payload, 1)),
        "invite_code": _decode_utf8(_field_bytes(payload, 2)),
        "invite_expiration": _field_varint(payload, 3),
        "group_name": _decode_utf8(_field_bytes(payload, 4)),
        "caption": _decode_utf8(_field_bytes(payload, 6)),
        "group_type": _field_varint(payload, 8),
    }


def _decode_payment_invite(payload: bytes) -> dict[str, Any]:
    return {
        "service_type": _field_varint(payload, 1),
        "expiry_timestamp": _field_varint(payload, 2),
    }


def _decode_pin_in_chat(payload: bytes) -> dict[str, Any]:
    key_bytes = _field_bytes(payload, 1)
    key: dict[str, Any] = {}
    if key_bytes:
        key = {
            "remote_jid": _decode_utf8(_field_bytes(key_bytes, 1)),
            "from_me": _field_bool(key_bytes, 2),
            "id": _decode_utf8(_field_bytes(key_bytes, 3)),
            "participant": _decode_utf8(_field_bytes(key_bytes, 4)),
        }
    return {
        "key": key,
        "type": _field_varint(payload, 2),
        "sender_timestamp_ms": _field_varint(payload, 3),
    }


def _decode_ptv_message(payload: bytes) -> dict[str, Any]:
    content = _decode_video(payload)
    content["ptv"] = True
    return content



def _decode_reaction(payload: bytes) -> dict[str, Any]:
    key_bytes = _field_bytes(payload, 1)
    key: dict[str, Any] = {}
    if key_bytes:
        key = {
            "remote_jid": _decode_utf8(_field_bytes(key_bytes, 1)),
            "from_me": _field_bool(key_bytes, 2) or False,
            "id": _decode_utf8(_field_bytes(key_bytes, 3)),
            "participant": _decode_utf8(_field_bytes(key_bytes, 4)),
        }
    text = _decode_utf8(_field_bytes(payload, 2)) or ""
    return {
        "key": key,
        "text": text,
        "target_id": key.get("id"),
        "target_participant": key.get("participant"),
        "sender_timestamp_ms": _field_varint(payload, 4),
        "is_removal": not bool(text),
    }


def _decode_msg_key(key_bytes: bytes | None) -> dict[str, Any]:
    if key_bytes is None:
        return {}
    return {
        "remote_jid": _decode_utf8(_field_bytes(key_bytes, 1)),
        "from_me": _field_bool(key_bytes, 2) or False,
        "id": _decode_utf8(_field_bytes(key_bytes, 3)),
        "participant": _decode_utf8(_field_bytes(key_bytes, 4)),
    }


def _decode_buttons_response(payload: bytes) -> dict[str, Any]:
    return {
        "selected_button_id": _decode_utf8(_field_bytes(payload, 1)),
        "selected_display_text": _decode_utf8(_field_bytes(payload, 2)),
    }


def _decode_list_response(payload: bytes) -> dict[str, Any]:
    single_select = _field_bytes(payload, 3)
    row_id = _decode_utf8(_field_bytes(single_select, 1)) if single_select else None
    return {
        "title": _decode_utf8(_field_bytes(payload, 1)),
        "selected_row_id": row_id,
        "description": _decode_utf8(_field_bytes(payload, 4)),
    }


def _decode_keep_in_chat(payload: bytes) -> dict[str, Any]:
    key_bytes = _field_bytes(payload, 1)
    return {
        "key": _decode_msg_key(key_bytes),
        "keep_type": _field_varint(payload, 2),
        "timestamp_ms": _field_varint(payload, 3),
    }


def _decode_context_info(payload: bytes) -> dict[str, Any] | None:

    if not payload:
        return None
    out: dict[str, Any] = {
        "stanza_id": None,
        "participant": None,
        "quoted_message": None,
        "remote_jid": None,
        "mentioned_jid": [],
        "is_forwarded": False,
        "forwarding_score": 0,
    }
    for field_no, wire_type, value in iter_fields(payload):
        if field_no == 1 and wire_type == 2:
            out["stanza_id"] = _decode_utf8(bytes(value))
        elif field_no == 2 and wire_type == 2:
            out["participant"] = _decode_utf8(bytes(value))
        elif field_no == 3 and wire_type == 2:
            quoted_raw = bytes(value)
            with contextlib.suppress(Exception):
                out["quoted_message"] = parse_message_payload(quoted_raw, allow_device_sent=False)
            out["quoted_message_raw"] = quoted_raw
        elif field_no == 4 and wire_type == 2:
            out["remote_jid"] = _decode_utf8(bytes(value))
        elif field_no == 15 and wire_type == 2:
            val = _decode_utf8(bytes(value))
            if val:
                out["mentioned_jid"].append(val)
        elif field_no == 21 and wire_type == 0:
            out["forwarding_score"] = int(value)
        elif field_no == 22 and wire_type == 0:
            out["is_forwarded"] = bool(value)

    if (
        not out["stanza_id"]
        and not out["participant"]
        and not out["quoted_message"]
        and not out["mentioned_jid"]
        and not out["is_forwarded"]
    ):
        return None
    return out


def _extract_context_info_payload(payload: bytes) -> bytes | None:
    # 1. Check extendedTextMessage (field 6) -> contextInfo (field 17)
    ext = _field_bytes(payload, 6)
    if ext:
        ctx = _field_bytes(ext, 17)
        if ctx:
            return ctx
    # 2. Check media messages (field 17)
    for f in (3, 4, 7, 8, 9, 26, 66):
        media = _field_bytes(payload, f)
        if media:
            ctx = _field_bytes(media, 17)
            if ctx:
                return ctx
    # 3. Check buttons/list (field 8)
    for f in (36, 42):
        interactive = _field_bytes(payload, f)
        if interactive:
            ctx = _field_bytes(interactive, 8)
            if ctx:
                return ctx
    return None


def parse_message_payload(payload: bytes, *, allow_device_sent: bool = True) -> dict[str, Any]:
    """Parse incoming Message payload into a normalized content summary."""
    summary: dict[str, Any] = {
        "text": None,
        "media_url": None,
        "reaction": None,
        "reaction_target_id": None,
        "reaction_target_participant": None,
        "is_reaction_removal": False,
        "destination_jid": None,
        "message_kind": "unknown",
        "content_type": "unknown",
        "content": {},
        "message_secret_b64": None,
        "sender_key_distribution": None,
        "context_info": None,
        "wrappers": [],
        "is_view_once": False,
        "is_ephemeral": False,
    }
    if not payload:
        return summary

    normalized_payload, wrappers = _unwrap_future_proof_message(payload)
    summary["wrappers"] = wrappers
    summary["is_view_once"] = any(w in {37, 55, 59} for w in wrappers)
    summary["is_ephemeral"] = 40 in wrappers


    message = wa_pb2.Message()
    with contextlib.suppress(Exception):
        message.ParseFromString(normalized_payload)

    text = message.conversation or message.extendedTextMessage.text or message.imageMessage.caption or None
    media_url = message.imageMessage.url or None
    destination_jid = message.deviceSentMessage.destinationJid or None

    reaction = None
    reaction_target_id = None
    reaction_payload = _field_bytes(normalized_payload, 46)
    if reaction_payload is not None:
        reaction_dict = _decode_reaction(reaction_payload)
        reaction = reaction_dict.get("text") or None
        reaction_target_id = reaction_dict.get("target_id") or None
        summary["message_kind"] = "reaction"
        summary["content_type"] = "reaction"
        summary["reaction"] = reaction
        summary["reaction_target_id"] = reaction_target_id
        summary["reaction_target_participant"] = reaction_dict.get("target_participant")
        summary["is_reaction_removal"] = reaction_dict.get("is_removal", False)
        summary["content"] = reaction_dict
    elif message.reactionMessage.key.id:
        reaction = message.reactionMessage.text or None
        reaction_target_id = message.reactionMessage.key.id
        summary["message_kind"] = "reaction"
        summary["content_type"] = "reaction"
        summary["reaction"] = reaction
        summary["reaction_target_id"] = reaction_target_id
        summary["reaction_target_participant"] = getattr(message.reactionMessage.key, "participant", None) or None
        summary["is_reaction_removal"] = not bool(message.reactionMessage.text)
        summary["content"] = {
            "key": {
                "id": reaction_target_id,
                "remote_jid": message.reactionMessage.key.remoteJid,
                "participant": summary["reaction_target_participant"],
            },
            "text": reaction or "",
            "target_id": reaction_target_id,
            "target_participant": summary["reaction_target_participant"],
            "is_removal": summary["is_reaction_removal"],
        }
    elif media_url:
        summary["message_kind"] = "media"
    elif text:
        summary["message_kind"] = "text"
        summary["content_type"] = "text"

    summary["text"] = text
    summary["media_url"] = media_url
    summary["destination_jid"] = destination_jid

    # Extract contextInfo (quoted messages, mentions, forwarding)
    ctx_payload = _extract_context_info_payload(normalized_payload)
    if ctx_payload is not None:
        summary["context_info"] = _decode_context_info(ctx_payload)

    direct_message_secret = _extract_context_message_secret_b64(_field_bytes(normalized_payload, 35))
    if direct_message_secret:
        summary["message_secret_b64"] = direct_message_secret

    sender_key_payload = _field_bytes(normalized_payload, 2)
    if sender_key_payload is not None:
        summary["sender_key_distribution"] = _decode_sender_key_distribution(sender_key_payload)

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
                if summary["reaction_target_participant"] is None:
                    summary["reaction_target_participant"] = nested.get("reaction_target_participant")
                if not summary["is_reaction_removal"] and nested.get("is_reaction_removal"):
                    summary["is_reaction_removal"] = True
                if summary["context_info"] is None and nested.get("context_info"):
                    summary["context_info"] = nested.get("context_info")
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
        (28, "group_invite", _decode_group_invite),
        (36, "list", _decode_list_message),
        (42, "buttons", _decode_buttons_message),
        (44, "payment_invite", _decode_payment_invite),
        (25, "template", _decode_template_message),
        (29, "template_button_reply", _decode_buttons_response),
        (39, "list_response", _decode_list_response),
        (43, "buttons_response", _decode_buttons_response),
        (51, "keep_in_chat", _decode_keep_in_chat),
        (63, "pin_in_chat", _decode_pin_in_chat),
        (66, "ptv", _decode_ptv_message),
    ]


    if summary["content_type"] == "unknown":
        for field_number, content_type, decoder in decoders:
            content_payload = _field_bytes(normalized_payload, field_number)
            if content_payload is None:
                continue
            content = decoder(content_payload)
            summary["content_type"] = content_type
            summary["content"] = content
            if content_type in {"image", "document", "audio", "video", "sticker", "ptv"}:
                url = content.get("url")
                if isinstance(url, str) and url:
                    summary["media_url"] = url
                    if summary["message_kind"] == "unknown":
                        summary["message_kind"] = "media"
            if content_type == "pin_in_chat":
                summary["message_kind"] = "pin_in_chat"
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
        content_map = cast("dict[str, object]", summary["content"])
        for key in ("caption", "title", "content_text", "name"):
            candidate = content_map.get(key)
            if isinstance(candidate, str) and candidate:
                summary["text"] = candidate
                if summary["message_kind"] == "unknown":
                    summary["message_kind"] = "text"
                break

    return summary

