"""Utilities for decoding incoming message nodes."""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING

from waton.core.entities import Message
from waton.protocol.binary_node import BinaryNode
from waton.protocol.signal_repo import SignalRepository
from waton.utils.message_content import parse_message_payload
from waton.utils.protocol_message import (
    decrypt_event_response,
    decrypt_poll_vote,
    extract_enc_event_response_message,
    extract_enc_reaction_message,
    extract_poll_update_message,
    extract_protocol_message,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from waton.client.client import WAClient


def _get_message_secret(client: WAClient, message_id: str) -> bytes | None:
    creds = client.creds
    if creds is None or not isinstance(message_id, str) or not message_id:
        return None
    additional_data = creds.additional_data or {}
    secrets_map = additional_data.get("message_secrets")
    if not isinstance(secrets_map, dict):
        return None
    raw = secrets_map.get(message_id)
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw.encode("ascii"))
        except Exception:
            return None
    return None


def _resolve_key_jid(message_key: dict[str, object] | None, fallback: str) -> str:
    if isinstance(message_key, dict):
        for candidate_key in ("participant", "remote_jid"):
            candidate = message_key.get(candidate_key)
            if isinstance(candidate, str) and candidate:
                return candidate
    return fallback


def _is_lid_user(jid: str | None) -> bool:
    return bool(jid and (jid.endswith("@lid") or jid.endswith("@hosted.lid")))


def _is_pn_user(jid: str | None) -> bool:
    return bool(jid and (jid.endswith("@s.whatsapp.net") or jid.endswith("@hosted")))


def _extract_sender_alt(node: BinaryNode, sender: str) -> str | None:
    attrs = node.attrs
    addressing_mode = attrs.get("addressing_mode") or ("lid" if _is_lid_user(sender) else "pn")
    if addressing_mode == "lid":
        candidate = (
            attrs.get("participant_pn")
            or attrs.get("sender_pn")
            or attrs.get("peer_recipient_pn")
            or attrs.get("recipient_pn")
        )
    else:
        candidate = (
            attrs.get("participant_lid")
            or attrs.get("sender_lid")
            or attrs.get("peer_recipient_lid")
            or attrs.get("recipient_lid")
        )
    return candidate if isinstance(candidate, str) and candidate else None


def extract_text_from_payload(
    payload: bytes,
) -> tuple[str | None, str | None, str | None, str | None, str | None, str]:
    summary = parse_message_payload(payload)
    return (
        summary["text"],
        summary["media_url"],
        summary["reaction"],
        summary["reaction_target_id"],
        summary["destination_jid"],
        summary["message_kind"],
    )


async def process_incoming_message(node: BinaryNode, client: WAClient) -> Message:
    raw = b""
    if node.content and isinstance(node.content, bytes):
        raw = node.content
    else:
        # Check for <enc v="2" type="msg|pkmsg"> child
        enc_node = (
            next((c for c in node.content if isinstance(c, BinaryNode) and c.tag == "enc"), None)
            if isinstance(node.content, list)
            else None
        )
        if enc_node and isinstance(enc_node.content, bytes):
            v = enc_node.attrs.get("v")
            enc_type = enc_node.attrs.get("type", "msg")
            if (v is None or v == "2") and client.creds:
                repo = SignalRepository(client.creds, client.storage)
                try:
                    from waton.client.messages import _unpad_random_max16

                    participant = node.attrs.get("participant") or node.attrs.get("from")
                    sender = participant if isinstance(participant, str) else None
                    if sender:
                        sender_alt = _extract_sender_alt(node, sender)
                        if sender_alt and ((_is_pn_user(sender) and _is_lid_user(sender_alt)) or (_is_lid_user(sender) and _is_pn_user(sender_alt))):
                            pn_jid = sender if _is_pn_user(sender) else sender_alt
                            lid_jid = sender if _is_lid_user(sender) else sender_alt
                            await repo.store_lid_pn_mapping(lid_jid, pn_jid)
                            await repo.migrate_session(pn_jid, lid_jid)

                        decryption_candidates: list[str] = []
                        if _is_pn_user(sender):
                            mapped_lid = await repo.get_lid_for_pn(sender)
                            if mapped_lid:
                                decryption_candidates.append(mapped_lid)
                        decryption_candidates.append(sender)
                        if _is_lid_user(sender):
                            mapped_pn = await repo.get_pn_for_lid(sender)
                            if mapped_pn:
                                decryption_candidates.append(mapped_pn)

                        tried: set[str] = set()
                        last_error: Exception | None = None
                        for candidate in decryption_candidates:
                            if candidate in tried:
                                continue
                            tried.add(candidate)
                            try:
                                decrypted = await repo.decrypt_message(candidate, enc_type, enc_node.content)
                                raw = _unpad_random_max16(decrypted)
                                last_error = None
                                break
                            except Exception as decrypt_error:
                                last_error = decrypt_error

                        if last_error is not None and not raw:
                            raise last_error
                except Exception as e:
                    err_text = str(e).lower()
                    if "old counter" in err_text:
                        logger.debug("Failed to decrypt message from %s: %r", participant, e)
                    else:
                        logger.warning("Failed to decrypt message from %s: %r", participant, e)

    protocol: dict[str, object] | None = None
    content_type: str | None = None
    content: dict[str, object] = {}
    message_secret_b64: str | None = None
    if raw:
        content_summary = parse_message_payload(raw)
        text = content_summary["text"]
        media_url = content_summary["media_url"]
        reaction = content_summary["reaction"]
        reaction_target_id = content_summary["reaction_target_id"]
        destination_jid = content_summary["destination_jid"]
        kind = content_summary["message_kind"]
        content_type = content_summary["content_type"]
        raw_content = content_summary["content"]
        if isinstance(raw_content, dict):
            content = raw_content
        raw_secret = content_summary["message_secret_b64"]
        if isinstance(raw_secret, str):
            message_secret_b64 = raw_secret
        protocol = extract_protocol_message(raw)
    else:
        text, media_url, reaction, reaction_target_id, destination_jid, kind = (None, None, None, None, None, "unknown")

    protocol_type: str | None = None
    protocol_code: int | None = None
    target_message_id: str | None = None
    edited_text: str | None = None
    ephemeral_expiration: int | None = None
    history_sync_type: int | None = None
    app_state_key_ids: list[str] = []
    encrypted_reaction: dict[str, object] | None = None
    poll_update: dict[str, object] | None = None
    event_response: dict[str, object] | None = None

    if isinstance(protocol, dict):
        raw_protocol_type = protocol.get("type_name")
        if isinstance(raw_protocol_type, str):
            protocol_type = raw_protocol_type
        raw_protocol_code = protocol.get("type_code")
        if isinstance(raw_protocol_code, int):
            protocol_code = raw_protocol_code
        raw_target_message_id = protocol.get("target_message_id")
        if isinstance(raw_target_message_id, str):
            target_message_id = raw_target_message_id
        raw_ephemeral_expiration = protocol.get("ephemeral_expiration")
        if isinstance(raw_ephemeral_expiration, int):
            ephemeral_expiration = raw_ephemeral_expiration

        edited_message = protocol.get("edited_message")
        if isinstance(edited_message, dict):
            raw_edited_text = edited_message.get("text")
            if isinstance(raw_edited_text, str):
                edited_text = raw_edited_text

        history_sync = protocol.get("history_sync")
        if isinstance(history_sync, dict):
            raw_history_sync_type = history_sync.get("sync_type")
            if isinstance(raw_history_sync_type, int):
                history_sync_type = raw_history_sync_type

        app_state_sync_key_share = protocol.get("app_state_sync_key_share")
        if isinstance(app_state_sync_key_share, dict):
            keys = app_state_sync_key_share.get("keys")
            if isinstance(keys, list):
                for key_item in keys:
                    if not isinstance(key_item, dict):
                        continue
                    key_id = key_item.get("key_id_b64")
                    if isinstance(key_id, str):
                        app_state_key_ids.append(key_id)

    if raw:
        enc_reaction = extract_enc_reaction_message(raw)
        if isinstance(enc_reaction, dict):
            encrypted_reaction = enc_reaction

        poll_update_raw = extract_poll_update_message(raw)
        if isinstance(poll_update_raw, dict):
            poll_update = poll_update_raw

        event_response_raw = extract_enc_event_response_message(raw)
        if isinstance(event_response_raw, dict):
            event_response = event_response_raw

    if poll_update is not None:
        poll_creation_message_id = poll_update.get("poll_creation_message_id")
        poll_vote = poll_update.get("vote")
        if isinstance(poll_creation_message_id, str) and isinstance(poll_vote, dict):
            secret = _get_message_secret(client, poll_creation_message_id)
            enc_payload_b64 = poll_vote.get("enc_payload_b64")
            enc_iv_b64 = poll_vote.get("enc_iv_b64")
            if (
                secret is not None
                and isinstance(enc_payload_b64, str)
                and isinstance(enc_iv_b64, str)
            ):
                try:
                    key_jid = _resolve_key_jid(
                        poll_update.get("poll_creation_key") if isinstance(poll_update, dict) else None,
                        node.attrs.get("from", ""),
                    )
                    poll_update["decrypted_vote"] = decrypt_poll_vote(
                        enc_payload_b64=enc_payload_b64,
                        enc_iv_b64=enc_iv_b64,
                        poll_message_id=poll_creation_message_id,
                        poll_creator_jid=key_jid,
                        voter_jid=node.attrs.get("participant") or node.attrs.get("from", ""),
                        poll_enc_key=secret,
                    )
                    poll_update["decrypted"] = True
                except Exception as exc:  # pragma: no cover - depends on secret correctness
                    poll_update["decrypt_error"] = str(exc)

    if event_response is not None:
        event_creation_message_id = event_response.get("event_creation_message_id")
        enc_payload_b64 = event_response.get("enc_payload_b64")
        enc_iv_b64 = event_response.get("enc_iv_b64")
        if (
            isinstance(event_creation_message_id, str)
            and isinstance(enc_payload_b64, str)
            and isinstance(enc_iv_b64, str)
        ):
            secret = _get_message_secret(client, event_creation_message_id)
            if secret is not None:
                try:
                    key_jid = _resolve_key_jid(
                        event_response.get("event_creation_key") if isinstance(event_response, dict) else None,
                        node.attrs.get("from", ""),
                    )
                    event_response["decrypted_response"] = decrypt_event_response(
                        enc_payload_b64=enc_payload_b64,
                        enc_iv_b64=enc_iv_b64,
                        event_message_id=event_creation_message_id,
                        event_creator_jid=key_jid,
                        responder_jid=node.attrs.get("participant") or node.attrs.get("from", ""),
                        event_enc_key=secret,
                    )
                    event_response["decrypted"] = True
                except Exception as exc:  # pragma: no cover - depends on secret correctness
                    event_response["decrypt_error"] = str(exc)

    if protocol_type == "REVOKE":
        kind = "protocol_revoke"
    elif protocol_type == "MESSAGE_EDIT":
        kind = "protocol_edit"
    elif encrypted_reaction is not None:
        kind = "reaction_encrypted"
    elif event_response is not None:
        kind = "event_response_encrypted"
    elif poll_update is not None:
        kind = "poll_update_encrypted"
    elif kind == "unknown" and isinstance(content_type, str) and content_type != "unknown":
        kind = content_type
    elif protocol_type is not None and kind == "unknown":
        kind = "protocol"

    return Message(
        id=node.attrs.get("id", ""),
        from_jid=node.attrs.get("from", ""),
        participant=node.attrs.get("participant"),
        text=text,
        media_url=media_url,
        reaction=reaction,
        reaction_target_id=reaction_target_id,
        destination_jid=destination_jid,
        protocol_type=protocol_type,
        protocol_code=protocol_code,
        target_message_id=target_message_id,
        edited_text=edited_text,
        ephemeral_expiration=ephemeral_expiration,
        history_sync_type=history_sync_type,
        app_state_key_ids=app_state_key_ids,
        encrypted_reaction=encrypted_reaction,
        poll_update=poll_update,
        event_response=event_response,
        content_type=content_type,
        content=content,
        message_secret_b64=message_secret_b64,
        message_type=kind if kind != "unknown" else node.attrs.get("type", "unknown"),
        raw_node=node,
    )
