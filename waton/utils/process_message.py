"""Utilities for decoding incoming message nodes."""

from __future__ import annotations

import logging
from waton.core.entities import Message
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import wa_pb2
from waton.protocol.signal_repo import SignalRepository
from waton.client.client import WAClient

logger = logging.getLogger(__name__)


def extract_text_from_payload(payload: bytes) -> str | None:
    pb = wa_pb2.Message()
    try:
        pb.ParseFromString(payload)
    except Exception:
        return payload.decode("utf-8", errors="ignore") or None
    return pb.conversation or pb.extendedTextMessage.text or None


async def process_incoming_message(node: BinaryNode, client: WAClient) -> Message:
    raw = b""
    if node.content and isinstance(node.content, bytes):
        raw = node.content
    else:
        # Check for <enc v="2" type="msg|pkmsg"> child
        enc_node = next((c for c in node.content if isinstance(c, BinaryNode) and c.tag == "enc"), None) if isinstance(node.content, list) else None
        if enc_node and isinstance(enc_node.content, bytes):
            v = enc_node.attrs.get("v")
            enc_type = enc_node.attrs.get("type", "msg")
            if v == "2" and client.creds:
                repo = SignalRepository(client.creds, client.storage)
                try:
                    from waton.client.messages import _unpad_random_max16
                    participant = node.attrs.get("participant") or node.attrs.get("from")
                    if participant:
                        decrypted = await repo.decrypt_message(participant, enc_type, enc_node.content)
                        raw = _unpad_random_max16(decrypted)
                except Exception as e:
                    logger.warning("Failed to decrypt message from %s: %r", participant, e)

    text = extract_text_from_payload(raw) if raw else None
    return Message(
        id=node.attrs.get("id", ""),
        from_jid=node.attrs.get("from", ""),
        participant=node.attrs.get("participant"),
        text=text,
        message_type=node.attrs.get("type", "unknown"),
        raw_node=node,
    )
