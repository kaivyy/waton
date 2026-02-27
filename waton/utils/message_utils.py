"""Helpers for constructing message-related binary nodes."""

from __future__ import annotations

import os

from waton.protocol.binary_node import BinaryNode


def generate_message_id(prefix: str = "") -> str:
    token = os.urandom(8).hex()
    return f"{prefix}{token}" if prefix else token


def build_text_message_node(to_jid: str, payload: bytes, msg_id: str | None = None) -> tuple[str, BinaryNode]:
    final_id = msg_id or generate_message_id()
    node = BinaryNode(
        tag="message",
        attrs={"to": to_jid, "id": final_id, "type": "text"},
        content=payload,
    )
    return final_id, node


def build_receipt_node(
    jid: str,
    message_ids: list[str],
    participant: str | None = None,
    receipt_type: str = "read",
) -> BinaryNode:
    attrs = {"to": jid, "type": receipt_type}
    if participant:
        attrs["participant"] = participant

    items = [BinaryNode(tag="item", attrs={"id": mid}) for mid in message_ids]
    return BinaryNode(tag="receipt", attrs=attrs, content=items)
