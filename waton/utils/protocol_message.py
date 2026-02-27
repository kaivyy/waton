"""Helpers for decoding `Message.protocolMessage` payloads.

This keeps protocol parsing centralized so both low-level receive normalization
and high-level message processing share the same behavior.
"""

from __future__ import annotations

import base64
from typing import Any

from waton.protocol.protobuf import wa_pb2
from waton.protocol.protobuf.wire import _iter_fields
from waton.utils.crypto import aes_decrypt, hmac_sha256

PROTOCOL_TYPE_NAMES: dict[int, str] = {
    0: "REVOKE",
    3: "EPHEMERAL_SETTING",
    5: "HISTORY_SYNC_NOTIFICATION",
    6: "APP_STATE_SYNC_KEY_SHARE",
    14: "MESSAGE_EDIT",
    17: "PEER_DATA_OPERATION_REQUEST_RESPONSE_MESSAGE",
    30: "GROUP_MEMBER_LABEL_CHANGE",
}

PROTOCOL_EVENT_TYPES: dict[int, str] = {
    0: "messages.revoke",
    3: "messages.ephemeral_setting",
    5: "messages.history_sync",
    6: "messages.app_state_sync_key_share",
    14: "messages.edit",
    30: "messages.group_member_label_change",
}


def protocol_event_type(type_code: int | None) -> str:
    if type_code is None:
        return "messages.protocol"
    return PROTOCOL_EVENT_TYPES.get(type_code, "messages.protocol")


def _field_bytes(payload: bytes, field_number: int) -> bytes | None:
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == field_number and wire_type == 2:
            return bytes(value)
    return None


def _decode_message_key(payload: bytes) -> dict[str, Any]:
    key: dict[str, Any] = {}
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == 1 and wire_type == 2:
            key["remote_jid"] = bytes(value).decode("utf-8", errors="ignore")
        elif field_no == 2 and wire_type == 0:
            key["from_me"] = bool(int(value))
        elif field_no == 3 and wire_type == 2:
            key["id"] = bytes(value).decode("utf-8", errors="ignore")
        elif field_no == 4 and wire_type == 2:
            key["participant"] = bytes(value).decode("utf-8", errors="ignore")
    return key


def _decode_poll_enc_value(payload: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field_no, wire_type, value in _iter_fields(payload):
        if wire_type != 2:
            continue
        if field_no == 1:
            out["enc_payload_b64"] = base64.b64encode(bytes(value)).decode("ascii")
        elif field_no == 2:
            out["enc_iv_b64"] = base64.b64encode(bytes(value)).decode("ascii")
    return out


def _decode_text_like(message: wa_pb2.Message) -> str | None:
    return message.conversation or message.extendedTextMessage.text or message.imageMessage.caption or None


def _decode_edited_message(payload: bytes) -> dict[str, Any]:
    edited = wa_pb2.Message()
    edited.ParseFromString(payload)
    return {
        "text": _decode_text_like(edited),
    }


def _decode_history_sync(payload: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field_no, wire_type, value in _iter_fields(payload):
        if wire_type == 0 and field_no == 6:
            out["sync_type"] = int(value)
        elif wire_type == 0 and field_no == 7:
            out["chunk_order"] = int(value)
        elif wire_type == 0 and field_no == 9:
            out["progress"] = int(value)
        elif wire_type == 0 and field_no == 10:
            out["oldest_msg_timestamp"] = int(value)
        elif wire_type == 2 and field_no == 12:
            out["peer_data_request_session_id"] = bytes(value).decode("utf-8", errors="ignore")
    return out


def _decode_app_state_sync_key_share(payload: bytes) -> dict[str, Any]:
    keys: list[dict[str, Any]] = []
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no != 1 or wire_type != 2:
            continue
        key_payload = bytes(value)
        key_item: dict[str, Any] = {}
        for nested_field_no, nested_wire_type, nested_value in _iter_fields(key_payload):
            if nested_field_no == 1 and nested_wire_type == 2:
                key_id_payload = bytes(nested_value)
                for key_id_field_no, key_id_wire_type, key_id_value in _iter_fields(key_id_payload):
                    if key_id_field_no == 1 and key_id_wire_type == 2:
                        key_bytes = bytes(key_id_value)
                        key_item["key_id_b64"] = base64.b64encode(key_bytes).decode("ascii")
            elif nested_field_no == 2 and nested_wire_type == 2:
                key_data_payload = bytes(nested_value)
                for data_field_no, data_wire_type, data_value in _iter_fields(key_data_payload):
                    if data_field_no == 1 and data_wire_type == 2:
                        key_item["key_data_size"] = len(bytes(data_value))
        if key_item:
            keys.append(key_item)
    return {
        "count": len(keys),
        "keys": keys,
    }


def _decode_peer_data_operation_response(payload: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"result_count": 0}
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == 2 and wire_type == 2:
            out["stanza_id"] = bytes(value).decode("utf-8", errors="ignore")
        elif field_no == 3 and wire_type == 2:
            out["result_count"] = int(out["result_count"]) + 1
    return out


def _decode_member_label(payload: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == 1 and wire_type == 2:
            out["label"] = bytes(value).decode("utf-8", errors="ignore")
        elif field_no == 2 and wire_type == 0:
            out["label_timestamp"] = int(value)
    return out


def extract_enc_reaction_message(payload: bytes) -> dict[str, Any] | None:
    """Extract top-level `Message.encReactionMessage` (field 56)."""
    reaction_payload = _field_bytes(payload, 56)
    if reaction_payload is None:
        return None

    out: dict[str, Any] = {}
    for field_no, wire_type, value in _iter_fields(reaction_payload):
        if wire_type != 2:
            continue
        if field_no == 1:
            out["target_key"] = _decode_message_key(bytes(value))
        elif field_no == 2:
            out["enc_payload_b64"] = base64.b64encode(bytes(value)).decode("ascii")
        elif field_no == 3:
            out["enc_iv_b64"] = base64.b64encode(bytes(value)).decode("ascii")

    key = out.get("target_key")
    if isinstance(key, dict):
        out["target_message_id"] = key.get("id")
    return out if out else None


def extract_poll_update_message(payload: bytes) -> dict[str, Any] | None:
    """Extract top-level `Message.pollUpdateMessage` (field 50)."""
    poll_update_payload = _field_bytes(payload, 50)
    if poll_update_payload is None:
        return None

    out: dict[str, Any] = {}
    for field_no, wire_type, value in _iter_fields(poll_update_payload):
        if field_no == 1 and wire_type == 2:
            out["poll_creation_key"] = _decode_message_key(bytes(value))
        elif field_no == 2 and wire_type == 2:
            out["vote"] = _decode_poll_enc_value(bytes(value))
        elif field_no == 4 and wire_type == 0:
            out["sender_timestamp_ms"] = int(value)

    poll_creation_key = out.get("poll_creation_key")
    if isinstance(poll_creation_key, dict):
        out["poll_creation_message_id"] = poll_creation_key.get("id")
    return out if out else None


def extract_enc_event_response_message(payload: bytes) -> dict[str, Any] | None:
    """Extract top-level `Message.encEventResponseMessage` (field 76)."""
    response_payload = _field_bytes(payload, 76)
    if response_payload is None:
        return None

    out: dict[str, Any] = {}
    for field_no, wire_type, value in _iter_fields(response_payload):
        if wire_type != 2:
            continue
        if field_no == 1:
            out["event_creation_key"] = _decode_message_key(bytes(value))
        elif field_no == 2:
            out["enc_payload_b64"] = base64.b64encode(bytes(value)).decode("ascii")
        elif field_no == 3:
            out["enc_iv_b64"] = base64.b64encode(bytes(value)).decode("ascii")

    event_creation_key = out.get("event_creation_key")
    if isinstance(event_creation_key, dict):
        out["event_creation_message_id"] = event_creation_key.get("id")
    return out if out else None


def _derive_message_addon_key(
    *,
    addon_label: str,
    message_id: str,
    creator_jid: str,
    actor_jid: str,
    message_secret: bytes,
) -> bytes:
    sign = b"".join(
        (
            message_id.encode("utf-8"),
            creator_jid.encode("utf-8"),
            actor_jid.encode("utf-8"),
            addon_label.encode("utf-8"),
            b"\x01",
        )
    )
    key0 = hmac_sha256(message_secret, bytes(32))
    return hmac_sha256(sign, key0)


def _decode_poll_vote_message(payload: bytes) -> dict[str, Any]:
    selected_options: list[bytes] = []
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == 1 and wire_type == 2:
            selected_options.append(bytes(value))
    return {
        "selected_options_b64": [base64.b64encode(opt).decode("ascii") for opt in selected_options],
    }


def decrypt_poll_vote(
    *,
    enc_payload_b64: str,
    enc_iv_b64: str,
    poll_message_id: str,
    poll_creator_jid: str,
    voter_jid: str,
    poll_enc_key: bytes,
) -> dict[str, Any]:
    enc_payload = base64.b64decode(enc_payload_b64.encode("ascii"))
    enc_iv = base64.b64decode(enc_iv_b64.encode("ascii"))
    dec_key = _derive_message_addon_key(
        addon_label="Poll Vote",
        message_id=poll_message_id,
        creator_jid=poll_creator_jid,
        actor_jid=voter_jid,
        message_secret=poll_enc_key,
    )
    aad = f"{poll_message_id}\x00{voter_jid}".encode("utf-8")
    plaintext = aes_decrypt(enc_payload, dec_key, enc_iv, aad)
    out = _decode_poll_vote_message(plaintext)
    out["sender_jid"] = voter_jid
    return out


def _decode_event_response_message(payload: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field_no, wire_type, value in _iter_fields(payload):
        if wire_type != 0:
            continue
        if field_no == 1:
            out["response_type"] = int(value)
        elif field_no == 2:
            out["timestamp_ms"] = int(value)
        elif field_no == 3:
            out["extra_guest_count"] = int(value)
    return out


def decrypt_event_response(
    *,
    enc_payload_b64: str,
    enc_iv_b64: str,
    event_message_id: str,
    event_creator_jid: str,
    responder_jid: str,
    event_enc_key: bytes,
) -> dict[str, Any]:
    enc_payload = base64.b64decode(enc_payload_b64.encode("ascii"))
    enc_iv = base64.b64decode(enc_iv_b64.encode("ascii"))
    dec_key = _derive_message_addon_key(
        addon_label="Event Response",
        message_id=event_message_id,
        creator_jid=event_creator_jid,
        actor_jid=responder_jid,
        message_secret=event_enc_key,
    )
    aad = f"{event_message_id}\x00{responder_jid}".encode("utf-8")
    plaintext = aes_decrypt(enc_payload, dec_key, enc_iv, aad)
    out = _decode_event_response_message(plaintext)
    out["sender_jid"] = responder_jid
    return out


def extract_protocol_message(payload: bytes) -> dict[str, Any] | None:
    protocol_payload: bytes | None = None
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == 12 and wire_type == 2:
            protocol_payload = bytes(value)
            break

    if protocol_payload is None:
        return None

    out: dict[str, Any] = {
        "type_code": None,
        "type_name": "UNKNOWN",
    }

    for field_no, wire_type, value in _iter_fields(protocol_payload):
        if field_no == 1 and wire_type == 2:
            out["key"] = _decode_message_key(bytes(value))
        elif field_no == 2 and wire_type == 0:
            type_code = int(value)
            out["type_code"] = type_code
            out["type_name"] = PROTOCOL_TYPE_NAMES.get(type_code, f"UNKNOWN_{type_code}")
        elif field_no == 4 and wire_type == 0:
            out["ephemeral_expiration"] = int(value)
        elif field_no == 5 and wire_type == 0:
            out["ephemeral_setting_timestamp"] = int(value)
        elif field_no == 6 and wire_type == 2:
            out["history_sync"] = _decode_history_sync(bytes(value))
        elif field_no == 7 and wire_type == 2:
            out["app_state_sync_key_share"] = _decode_app_state_sync_key_share(bytes(value))
        elif field_no == 14 and wire_type == 2:
            out["edited_message"] = _decode_edited_message(bytes(value))
        elif field_no == 15 and wire_type == 0:
            out["timestamp_ms"] = int(value)
        elif field_no == 17 and wire_type == 2:
            out["peer_data_operation_response"] = _decode_peer_data_operation_response(bytes(value))
        elif field_no == 27 and wire_type == 2:
            out["member_label"] = _decode_member_label(bytes(value))

    key = out.get("key")
    if isinstance(key, dict):
        out["target_message_id"] = key.get("id")

    return out
