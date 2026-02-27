from __future__ import annotations

import asyncio
import base64
import time
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from waton.core.jid import S_WHATSAPP_NET
from waton.protocol.binary_node import BinaryNode
from waton.utils.message_content import parse_message_payload
from waton.utils.protocol_message import (
    extract_enc_event_response_message,
    extract_enc_reaction_message,
    extract_poll_update_message,
    extract_protocol_message,
    protocol_event_type,
)

if TYPE_CHECKING:
    from waton.protocol.signal_repo import SignalRepository

IncomingNodeHandler = Callable[[BinaryNode], Awaitable[None]]


def _unpad_random_max16(plaintext: bytes) -> bytes:
    if not plaintext:
        return plaintext
    pad_len = plaintext[-1]
    if pad_len == 0 or pad_len > len(plaintext):
        return plaintext
    for idx in range(1, pad_len + 1):
        if plaintext[-idx] != pad_len:
            return plaintext
    return plaintext[:-pad_len]


def _children(node: BinaryNode) -> list[BinaryNode]:
    if isinstance(node.content, list):
        return [child for child in node.content if isinstance(child, BinaryNode)]
    return []


def _get_child(node: BinaryNode, tag: str) -> BinaryNode | None:
    for child in _children(node):
        if child.tag == tag:
            return child
    return None


def _timestamp(value: str | None) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def _content_to_str(content: object) -> str:
    if isinstance(content, (bytes, bytearray)):
        return bytes(content).decode("utf-8", errors="ignore")
    if isinstance(content, str):
        return content
    return ""


def _content_to_bytes(content: object) -> bytes:
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8")
    return b""


def _content_to_b64(content: object) -> str:
    return base64.b64encode(_content_to_bytes(content)).decode("ascii")


def _attr_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _status_from_receipt_type(receipt_type: str) -> str:
    if receipt_type in {"read", "read-self"}:
        return "read"
    if receipt_type in {"played", "played-self"}:
        return "played"
    if receipt_type in {"delivery", "sender"}:
        return "delivery"
    return receipt_type


def _jid_userpart(value: str | None) -> str:
    if not value:
        return ""
    without_device = value.split(":", 1)[0]
    return without_device.split("@", 1)[0]


def _collect_item_ids(node: BinaryNode) -> list[str]:
    item_ids: list[str] = []
    for child in _children(node):
        if child.tag == "item":
            item_id = child.attrs.get("id")
            if item_id:
                item_ids.append(item_id)
            continue
        for grand_child in _children(child):
            if grand_child.tag != "item":
                continue
            nested_id = grand_child.attrs.get("id")
            if nested_id:
                item_ids.append(nested_id)
    return item_ids


def _find_nested_child(node: BinaryNode, tag: str) -> BinaryNode | None:
    direct = _get_child(node, tag)
    if direct:
        return direct
    for child in _children(node):
        nested = _get_child(child, tag)
        if nested:
            return nested
    return None


def classify_incoming_node(node: BinaryNode) -> str:
    if node.tag == "message":
        return "message"
    if node.tag == "receipt":
        return "receipt"
    if node.tag == "notification":
        return "notification"
    if node.tag == "call":
        return "call"
    if node.tag == "ack":
        return "ack"
    if node.tag == "ib":
        return "ib"
    return "other"


async def _extract_message_payload(node: BinaryNode, signal_repo: SignalRepository) -> bytes:
    enc_node = _get_child(node, "enc")
    if enc_node and isinstance(enc_node.content, (bytes, bytearray)):
        jid = node.attrs.get("participant") or node.attrs.get("from")
        enc_type = enc_node.attrs.get("type", "msg")
        if jid:
            return await signal_repo.decrypt_message(jid, enc_type, bytes(enc_node.content))
        if hasattr(signal_repo, "decrypt_message_node"):
            return await signal_repo.decrypt_message_node(node)
        return b""

    if isinstance(node.content, (bytes, bytearray)):
        return bytes(node.content)
    if isinstance(node.content, str):
        return node.content.encode("utf-8")
    if hasattr(signal_repo, "decrypt_message_node"):
        return await signal_repo.decrypt_message_node(node)
    return b""


async def decode_incoming_message_node(node: BinaryNode, signal_repo: SignalRepository) -> dict[str, Any]:
    plaintext = await _extract_message_payload(node, signal_repo)
    payload = _unpad_random_max16(plaintext) if _get_child(node, "enc") is not None else plaintext
    summary = parse_message_payload(payload)
    message_payload = {
        "id": node.attrs.get("id"),
        "from": node.attrs.get("from"),
        "participant": node.attrs.get("participant"),
        "timestamp": _timestamp(node.attrs.get("t")),
        "stanza_type": node.attrs.get("type"),
        "text": summary["text"],
        "media_url": summary["media_url"],
        "reaction": summary["reaction"],
        "reaction_target_id": summary["reaction_target_id"],
        "destination_jid": summary["destination_jid"],
        "content_type": summary["content_type"],
        "content": summary["content"],
        "message_secret_b64": summary["message_secret_b64"],
    }

    protocol = extract_protocol_message(payload)
    if protocol is not None:
        return {
            "type": protocol_event_type(protocol.get("type_code")),
            "protocol": protocol,
            "message": message_payload,
        }

    reaction = summary["reaction"]
    reaction_target_id = summary["reaction_target_id"]

    if reaction is not None:
        return {
            "type": "messages.reaction",
            "reaction": {
                "text": reaction,
                "target_id": reaction_target_id,
                "from": node.attrs.get("from"),
            },
            "message": message_payload,
        }

    enc_reaction = extract_enc_reaction_message(payload)
    if enc_reaction is not None:
        message_payload["encrypted_reaction"] = enc_reaction
        return {
            "type": "messages.reaction_encrypted",
            "encrypted_reaction": enc_reaction,
            "message": message_payload,
        }

    enc_event_response = extract_enc_event_response_message(payload)
    if enc_event_response is not None:
        message_payload["event_response"] = enc_event_response
        return {
            "type": "messages.event_response_encrypted",
            "event_response": enc_event_response,
            "message": message_payload,
        }

    poll_update = extract_poll_update_message(payload)
    if poll_update is not None:
        message_payload["poll_update"] = poll_update
        return {
            "type": "messages.poll_update_encrypted",
            "poll_update": poll_update,
            "message": message_payload,
        }

    return {"type": "messages.upsert", "message": message_payload}


def decode_receipt_node(node: BinaryNode) -> dict[str, Any]:
    item_ids = _collect_item_ids(node)
    root_id = node.attrs.get("id")
    message_ids = item_ids if item_ids else ([root_id] if root_id else [])
    receipt_type = node.attrs.get("type", "delivery")
    is_retry = receipt_type == "retry"
    status = _status_from_receipt_type(receipt_type)

    retry_payload: dict[str, Any] | None = None
    if is_retry:
        retry_node = _find_nested_child(node, "retry")
        retry_payload = {
            "count": _timestamp(retry_node.attrs.get("count")) if retry_node else 0,
            "id": (retry_node.attrs.get("id") if retry_node else None) or root_id,
            "timestamp": _timestamp(retry_node.attrs.get("t")) if retry_node else 0,
            "version": retry_node.attrs.get("v") if retry_node else None,
        }

    event_type = "messages.retry_request" if is_retry else "messages.receipt"

    return {
        "type": event_type,
        "receipt": {
            "id": root_id,
            "from": node.attrs.get("from"),
            "participant": node.attrs.get("participant"),
            "receipt_type": receipt_type,
            "status": status,
            "timestamp": _timestamp(node.attrs.get("t")),
            "message_ids": message_ids,
            "is_read": status == "read",
            "is_played": status == "played",
            "is_delivery": status == "delivery",
            "is_retry": is_retry,
            "retry": retry_payload,
        },
    }


def _collect_notification_participants(node: BinaryNode | None) -> list[str]:
    if node is None:
        return []
    participants: list[str] = []
    for key in ("jid", "participant"):
        value = node.attrs.get(key)
        if value:
            participants.append(value)
    for child in _children(node):
        for key in ("jid", "participant"):
            value = child.attrs.get(key)
            if value:
                participants.append(value)
    # De-duplicate while preserving order.
    return list(dict.fromkeys(participants))


def _decode_newsletter_event(node: BinaryNode, first_child: BinaryNode | None) -> dict[str, Any] | None:
    from_jid = node.attrs.get("from", "")
    if not from_jid.endswith("@newsletter") or first_child is None:
        return None

    if first_child.tag == "reaction":
        reaction_text = None
        reaction_child = _get_child(first_child, "reaction")
        if reaction_child is not None:
            if isinstance(reaction_child.content, (bytes, bytearray)):
                reaction_text = bytes(reaction_child.content).decode("utf-8", errors="ignore")
            elif isinstance(reaction_child.content, str):
                reaction_text = reaction_child.content
        return {
            "type": "reaction",
            "newsletter_jid": from_jid,
            "message_id": first_child.attrs.get("message_id"),
            "reaction": reaction_text,
            "author": node.attrs.get("participant"),
        }

    if first_child.tag == "view":
        count = 0
        if isinstance(first_child.content, (bytes, bytearray)):
            raw = bytes(first_child.content).decode("utf-8", errors="ignore")
            if raw.isdigit():
                count = int(raw)
        elif isinstance(first_child.content, str) and first_child.content.isdigit():
            count = int(first_child.content)
        return {
            "type": "view",
            "newsletter_jid": from_jid,
            "message_id": first_child.attrs.get("message_id"),
            "count": count,
            "author": node.attrs.get("participant"),
        }

    if first_child.tag == "participant":
        return {
            "type": "participant",
            "newsletter_jid": from_jid,
            "author": node.attrs.get("participant"),
            "user": first_child.attrs.get("jid"),
            "action": first_child.attrs.get("action"),
            "new_role": first_child.attrs.get("role"),
        }

    if first_child.tag == "update":
        settings_node = _get_child(first_child, "settings")
        update: dict[str, str] = {}
        if settings_node is not None:
            name_node = _get_child(settings_node, "name")
            description_node = _get_child(settings_node, "description")
            if name_node is not None:
                update["name"] = _content_to_str(name_node.content)
            if description_node is not None:
                update["description"] = _content_to_str(description_node.content)
        return {
            "type": "settings_update",
            "newsletter_jid": from_jid,
            "author": node.attrs.get("participant"),
            "update": update,
        }

    return None


def _decode_encrypt_notification(node: BinaryNode, first_child: BinaryNode | None) -> dict[str, Any] | None:
    if node.attrs.get("type") != "encrypt" or first_child is None:
        return None

    if first_child.tag == "identity":
        device_identity = _get_child(first_child, "device-identity")
        return {
            "type": "identity",
            "jid": first_child.attrs.get("jid"),
            "has_device_identity": device_identity is not None,
            "device_identity_key_index": device_identity.attrs.get("key-index") if device_identity else None,
            "device_identity_b64": _content_to_b64(device_identity.content) if device_identity else None,
        }

    if first_child.tag == "count":
        return {
            "type": "count",
            "value": _content_to_str(first_child.content),
        }

    if first_child.tag == "app-state-sync-key-share":
        key_ids: list[str] = []
        for child in _children(first_child):
            if child.tag in {"key-id", "id"}:
                raw = _content_to_bytes(child.content)
                if raw:
                    key_ids.append(base64.b64encode(raw).decode("ascii"))
        return {
            "type": "app_state_sync_key_share",
            "key_ids_b64": key_ids,
        }

    return {
        "type": first_child.tag,
        "attrs": dict(first_child.attrs),
    }


def _decode_link_code_notification(node: BinaryNode) -> dict[str, Any] | None:
    if node.attrs.get("type") != "link_code_companion_reg":
        return None

    mapping = {
        "link_code_pairing_wrapped_companion_ephemeral_pub": "ephemeral_pub_b64",
        "companion_server_auth_key_pub": "companion_server_auth_key_pub_b64",
        "primary_identity_pub": "primary_identity_pub_b64",
        "adv_secret": "adv_secret_b64",
    }
    out: dict[str, Any] = {"type": "link_code_companion_reg"}
    for child in _children(node):
        key = mapping.get(child.tag)
        if key:
            out[key] = _content_to_b64(child.content)
    return out


def _decode_privacy_token_notification(node: BinaryNode) -> dict[str, Any] | None:
    if node.attrs.get("type") != "privacy_token":
        return None

    token_container = _get_child(node, "privacy_token")
    if token_container is None:
        return {"type": "privacy_token", "tokens": {}}

    tokens: dict[str, str] = {}
    for token_node in _children(token_container):
        if token_node.tag != "token":
            continue
        jid = token_node.attrs.get("jid")
        if not jid:
            continue
        tokens[jid] = _content_to_b64(token_node.content)
    return {"type": "privacy_token", "tokens": tokens}


def _decode_mediaretry_notification(node: BinaryNode) -> dict[str, Any] | None:
    if node.attrs.get("type") != "mediaretry":
        return None

    mediaretry_node = _get_child(node, "mediaretry")
    if mediaretry_node is None:
        return {"type": "mediaretry"}

    result_node = _get_child(mediaretry_node, "result")
    direct_path_node = _get_child(mediaretry_node, "direct_path")
    return {
        "type": "mediaretry",
        "message_id": mediaretry_node.attrs.get("id"),
        "to": mediaretry_node.attrs.get("to"),
        "result_code": result_node.attrs.get("code") if result_node else None,
        "result_payload_b64": _content_to_b64(result_node.content) if result_node else None,
        "direct_path": _content_to_str(direct_path_node.content) if direct_path_node else None,
    }


def _decode_history_sync_notification(node: BinaryNode, first_child: BinaryNode | None) -> dict[str, Any] | None:
    if first_child is None:
        return None
    node_type = node.attrs.get("type")
    if node_type not in {"hist_sync", "history", "server_sync"} and first_child.tag not in {"hist_sync", "history"}:
        return None

    history_node = first_child if first_child.tag in {"hist_sync", "history"} else _get_child(first_child, "history")
    if history_node is None:
        history_node = first_child

    details: dict[str, Any] = {
        "type": "history_sync",
        "sync_type": history_node.attrs.get("sync_type") or history_node.attrs.get("type"),
        "chunk_order": _timestamp(history_node.attrs.get("chunk_order")),
        "progress": _timestamp(history_node.attrs.get("progress")),
        "oldest_msg_timestamp": _timestamp(history_node.attrs.get("oldest_msg_timestamp")),
        "full_sync": _attr_bool(history_node.attrs.get("full")),
        "request_id": history_node.attrs.get("request_id"),
    }
    payload = _content_to_bytes(history_node.content)
    if payload:
        details["payload_b64"] = base64.b64encode(payload).decode("ascii")
        details["payload_size"] = len(payload)
    return details


def _decode_server_sync_notification(node: BinaryNode, first_child: BinaryNode | None) -> dict[str, Any] | None:
    if node.attrs.get("type") not in {"server_sync", "ib"}:
        return None
    if first_child is None:
        return {"type": "server_sync"}

    actions: list[dict[str, Any]] = []
    for action_node in _children(node):
        entry: dict[str, Any] = {
            "tag": action_node.tag,
            "attrs": dict(action_node.attrs),
        }
        content_bytes = _content_to_bytes(action_node.content)
        if content_bytes:
            entry["payload_b64"] = base64.b64encode(content_bytes).decode("ascii")
        actions.append(entry)

    return {
        "type": "server_sync",
        "actions": actions,
    }


def _decode_account_sync_notification(node: BinaryNode, first_child: BinaryNode | None) -> dict[str, Any] | None:
    if node.attrs.get("type") not in {"account_sync", "devices", "account"}:
        return None

    account_event: dict[str, Any] = {
        "type": "account_sync",
        "from": node.attrs.get("from"),
        "action": first_child.tag if first_child else None,
        "attrs": dict(first_child.attrs) if first_child else {},
    }
    if first_child is None:
        return account_event

    linked_devices: list[dict[str, Any]] = []
    for child in _children(first_child):
        if child.tag not in {"device", "companion"}:
            continue
        linked_devices.append(
            {
                "jid": child.attrs.get("jid"),
                "platform": child.attrs.get("platform"),
                "last_active": _timestamp(child.attrs.get("last_active")),
                "is_trusted": _attr_bool(child.attrs.get("trusted")),
            }
        )
    if linked_devices:
        account_event["linked_devices"] = linked_devices
    return account_event


def decode_call_node(node: BinaryNode) -> dict[str, Any]:
    call_child = _children(node)[0] if _children(node) else None
    call_from = (
        call_child.attrs.get("from")
        if call_child is not None
        else None
    ) or (call_child.attrs.get("call-creator") if call_child is not None else None) or node.attrs.get("from")
    call_id = call_child.attrs.get("call-id") if call_child is not None else None
    is_group = False
    is_video = False
    group_jid = None
    if call_child is not None:
        is_group = call_child.attrs.get("type") == "group" or bool(call_child.attrs.get("group-jid"))
        is_video = _get_child(call_child, "video") is not None
        group_jid = call_child.attrs.get("group-jid")
    return {
        "type": "messages.call",
        "call": {
            "chat_id": node.attrs.get("from"),
            "from": call_from,
            "id": call_id,
            "timestamp": _timestamp(node.attrs.get("t")),
            "offline": _attr_bool(node.attrs.get("offline")),
            "status": call_child.tag if call_child is not None else "unknown",
            "is_video": is_video,
            "is_group": is_group,
            "group_jid": group_jid,
        },
    }


def decode_notification_node(node: BinaryNode) -> dict[str, Any]:
    child_nodes = _children(node)
    child_tags = [child.tag for child in child_nodes]
    first_child = child_nodes[0] if child_nodes else None
    kind = node.attrs.get("type") or (child_tags[0] if child_tags else "unknown")

    group_event: dict[str, Any] | None = None
    if node.attrs.get("type") == "w:gp2" and first_child is not None:
        participants = _collect_notification_participants(first_child)
        if first_child.tag in {"add", "remove", "promote", "demote", "modify", "leave"}:
            group_event = {
                "kind": "participants",
                "action": first_child.tag,
                "participants": participants,
            }
        elif first_child.tag == "announcement":
            group_event = {
                "kind": "metadata",
                "action": "announce",
                "value": "on",
            }
        elif first_child.tag == "not_announcement":
            group_event = {
                "kind": "metadata",
                "action": "announce",
                "value": "off",
            }
        elif first_child.tag == "locked":
            group_event = {
                "kind": "metadata",
                "action": "restrict",
                "value": "on",
            }
        elif first_child.tag == "unlocked":
            group_event = {
                "kind": "metadata",
                "action": "restrict",
                "value": "off",
            }
        elif first_child.tag == "membership_approval_mode":
            approval = _get_child(first_child, "group_join")
            group_event = {
                "kind": "metadata",
                "action": "join_approval_mode",
                "value": approval.attrs.get("state") if approval else None,
            }
        elif first_child.tag == "member_add_mode":
            group_event = {
                "kind": "metadata",
                "action": "member_add_mode",
                "value": _content_to_str(first_child.content),
            }
        elif first_child.tag == "create":
            group_event = {
                "kind": "create",
                "subject": first_child.attrs.get("subject"),
                "participants": participants,
            }
        elif first_child.tag == "created_membership_requests":
            group_event = {
                "kind": "membership_requests",
                "action": "created",
                "participants": participants,
                "request_method": first_child.attrs.get("request_method"),
            }
        elif first_child.tag == "revoked_membership_requests":
            acting = _jid_userpart(node.attrs.get("participant"))
            affected = _jid_userpart(participants[0] if participants else None)
            action = "revoked" if acting and acting == affected else "rejected"
            group_event = {
                "kind": "membership_requests",
                "action": action,
                "participants": participants,
            }
        elif first_child.tag in {"subject", "description", "ephemeral", "invite", "announce", "restrict"}:
            metadata_value: str | None
            if first_child.tag == "description":
                body = _get_child(first_child, "body")
                metadata_value = _content_to_str(body.content) if body else None
            elif first_child.tag == "invite":
                metadata_value = first_child.attrs.get("code")
            else:
                metadata_value = first_child.attrs.get("value") or first_child.attrs.get("subject")
            group_event = {
                "kind": "metadata",
                "action": first_child.tag,
                "value": metadata_value,
            }
        elif first_child.tag == "not_ephemeral":
            group_event = {
                "kind": "metadata",
                "action": "ephemeral",
                "value": "0",
            }

    newsletter_event = _decode_newsletter_event(node, first_child)
    encrypt_event = _decode_encrypt_notification(node, first_child)
    link_code_event = _decode_link_code_notification(node)
    privacy_token_event = _decode_privacy_token_notification(node)
    media_retry_event = _decode_mediaretry_notification(node)
    history_sync_event = _decode_history_sync_notification(node, first_child)
    server_sync_event = _decode_server_sync_notification(node, first_child)
    account_sync_event = _decode_account_sync_notification(node, first_child)

    return {
        "type": "messages.notification",
        "notification": {
            "id": node.attrs.get("id"),
            "from": node.attrs.get("from"),
            "participant": node.attrs.get("participant"),
            "timestamp": _timestamp(node.attrs.get("t")),
            "kind": kind,
            "children": child_tags,
            "protocol": {
                "namespace": node.attrs.get("type"),
                "action": first_child.tag if first_child else None,
                "attrs": dict(first_child.attrs) if first_child else {},
            },
            "group_event": group_event,
            "newsletter_event": newsletter_event,
            "encrypt_event": encrypt_event,
            "link_code_event": link_code_event,
            "privacy_token_event": privacy_token_event,
            "media_retry_event": media_retry_event,
            "history_sync_event": history_sync_event,
            "server_sync_event": server_sync_event,
            "account_sync_event": account_sync_event,
        },
    }


def decode_ack_node(node: BinaryNode) -> dict[str, Any]:
    attrs = dict(node.attrs)
    if attrs.get("class") == "message" and attrs.get("error"):
        return {
            "type": "messages.bad_ack",
            "bad_ack": {
                "message_id": attrs.get("id"),
                "remote_jid": attrs.get("from") or attrs.get("to"),
                "error": attrs.get("error"),
                "phash": attrs.get("phash"),
                "attrs": attrs,
            },
        }
    return {"type": "messages.ack", "ack": attrs}


def decode_ib_node(node: BinaryNode) -> dict[str, Any]:
    return {
        "type": "messages.protocol_notification",
        "protocol_notification": {
            "from": node.attrs.get("from"),
            "children": [child.tag for child in _children(node)],
        },
    }


def build_message_ack(node: BinaryNode, error_code: int | None = None) -> BinaryNode:
    attrs: dict[str, str] = {
        "to": node.attrs.get("from", "s.whatsapp.net"),
        "class": node.tag,
    }
    for key in ("id", "participant", "recipient", "type", "t"):
        value = node.attrs.get(key)
        if value:
            attrs[key] = value
    if error_code is not None:
        attrs["error"] = str(error_code)
    return BinaryNode(tag="ack", attrs=attrs)


def build_retry_receipt_node(node: BinaryNode, retry_count: int, timestamp: int | None = None) -> BinaryNode:
    message_id = node.attrs.get("id", "")
    attrs: dict[str, str] = {
        "to": node.attrs.get("from", "s.whatsapp.net"),
        "id": message_id,
        "type": "retry",
    }
    participant = node.attrs.get("participant")
    if participant:
        attrs["participant"] = participant

    retry_ts = int(time.time()) if timestamp is None else int(timestamp)
    retry_child = BinaryNode(
        tag="retry",
        attrs={
            "count": str(retry_count),
            "id": message_id,
            "t": str(retry_ts),
            "v": "1",
        },
    )
    return BinaryNode(tag="receipt", attrs=attrs, content=[retry_child])


def build_call_reject_node(
    *,
    call_id: str,
    call_from: str,
    timestamp: int | None = None,
    call_to: str | None = None,
) -> BinaryNode:
    reject_timestamp = int(time.time()) if timestamp is None else int(timestamp)
    attrs = {
        "to": call_to or call_from,
        "id": call_id,
        "t": str(reject_timestamp),
    }
    reject = BinaryNode(
        tag="reject",
        attrs={
            "call-id": call_id,
            "call-creator": call_from,
            "count": "0",
        },
    )
    return BinaryNode(tag="call", attrs=attrs, content=[reject])


def build_placeholder_resend_request(
    *,
    message_id: str,
    remote_jid: str,
    participant: str | None = None,
    timestamp: int | None = None,
) -> BinaryNode:
    item_attrs: dict[str, str] = {
        "id": message_id,
        "jid": remote_jid,
    }
    if participant:
        item_attrs["participant"] = participant
    if timestamp is not None:
        item_attrs["t"] = str(int(timestamp))

    return BinaryNode(
        tag="iq",
        attrs={
            "to": S_WHATSAPP_NET,
            "type": "set",
            "xmlns": "placeholder",
        },
        content=[
            BinaryNode(
                tag="placeholder",
                attrs={},
                content=[BinaryNode(tag="item", attrs=item_attrs)],
            )
        ],
    )


class OfflineNodeProcessor:
    """Queue and drain incoming nodes in a predictable order.

    Baileys keeps separate lanes for high-priority protocol traffic and regular
    message traffic. This class provides a lightweight equivalent for Python.
    """

    _PRIORITY_LANES = (
        "receipt",
        "notification",
        "call",
        "ack",
        "ib",
        "message",
        "other",
    )

    def __init__(self, *, max_queue_size: int = 1024) -> None:
        self.max_queue_size = max(1, int(max_queue_size))
        self._lanes: dict[str, list[BinaryNode]] = {lane: [] for lane in self._PRIORITY_LANES}

    def queued_count(self) -> int:
        return sum(len(items) for items in self._lanes.values())

    def has_pending(self) -> bool:
        return self.queued_count() > 0

    def clear(self) -> None:
        for lane in self._lanes.values():
            lane.clear()

    def enqueue(self, node: BinaryNode) -> None:
        lane = classify_incoming_node(node)
        if lane not in self._lanes:
            lane = "other"
        current_size = self.queued_count()
        if current_size >= self.max_queue_size:
            self._drop_oldest_low_priority()
        self._lanes[lane].append(node)

    def _drop_oldest_low_priority(self) -> None:
        for lane in ("other", "message", "ib", "ack", "call", "notification", "receipt"):
            if self._lanes[lane]:
                self._lanes[lane].pop(0)
                return

    def pop_next(self) -> BinaryNode | None:
        for lane in self._PRIORITY_LANES:
            if self._lanes[lane]:
                return self._lanes[lane].pop(0)
        return None

    async def drain(
        self,
        handler: "IncomingNodeHandler",
        *,
        yield_every: int = 20,
        max_items: int | None = None,
    ) -> int:
        processed = 0
        bounded = max_items is not None and max_items >= 0
        while self.has_pending():
            if bounded and max_items is not None and processed >= max_items:
                break
            node = self.pop_next()
            if node is None:
                break
            await handler(node)
            processed += 1
            if yield_every > 0 and processed % yield_every == 0:
                await asyncio.sleep(0)
        return processed


async def drain_nodes_with_buffer(
    nodes: list[BinaryNode],
    handler: "IncomingNodeHandler",
    *,
    max_queue_size: int = 1024,
    yield_every: int = 20,
) -> int:
    """Process nodes through OfflineNodeProcessor priority lanes."""
    processor = OfflineNodeProcessor(max_queue_size=max_queue_size)
    for node in nodes:
        processor.enqueue(node)
    return await processor.drain(handler, yield_every=yield_every)


async def normalize_incoming_node(node: BinaryNode, signal_repo: SignalRepository | None) -> dict[str, Any] | None:
    kind = classify_incoming_node(node)
    if kind == "message":
        if signal_repo is None:
            return None
        return await decode_incoming_message_node(node, signal_repo)
    if kind == "receipt":
        return decode_receipt_node(node)
    if kind == "notification":
        return decode_notification_node(node)
    if kind == "call":
        return decode_call_node(node)
    if kind == "ack":
        return decode_ack_node(node)
    if kind == "ib":
        return decode_ib_node(node)
    return None
