"""Utilities for decoding incoming message nodes."""

from __future__ import annotations

from pywa.core.entities import Message
from pywa.protocol.binary_node import BinaryNode
from pywa.protocol.protobuf import wa_pb2


def extract_text_from_payload(payload: bytes) -> str | None:
    pb = wa_pb2.Message()
    try:
        pb.ParseFromString(payload)
    except Exception:
        return payload.decode("utf-8", errors="ignore") or None
    return pb.conversation or pb.extendedTextMessage.text or None


def process_incoming_message(node: BinaryNode) -> Message:
    raw = node.content if isinstance(node.content, bytes) else b""
    text = extract_text_from_payload(raw) if raw else None
    return Message(
        id=node.attrs.get("id", ""),
        from_jid=node.attrs.get("from", ""),
        participant=node.attrs.get("participant"),
        text=text,
        message_type=node.attrs.get("type", "unknown"),
        raw_node=node,
    )
