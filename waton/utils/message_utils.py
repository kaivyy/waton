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


import time


def build_receipt_node(
    jid: str,
    message_ids: list[str],
    participant: str | None = None,
    receipt_type: str = "read",
) -> BinaryNode:
    is_1on1 = "@s.whatsapp.net" in jid or "@lid" in jid or "@hosted" in jid
    attrs: dict[str, str] = {}
    if receipt_type == "sender" and is_1on1:
        attrs["recipient"] = jid
        attrs["to"] = participant or jid
    else:
        attrs["to"] = jid
        if participant:
            attrs["participant"] = participant

    if receipt_type and receipt_type != "delivery":
        attrs["type"] = receipt_type
    if receipt_type in {"read", "read-self", "played", "played-self"}:
        attrs["t"] = str(int(time.time()))

    if not message_ids:
        return BinaryNode(tag="receipt", attrs=attrs, content=None)

    if len(message_ids) == 1:
        attrs["id"] = message_ids[0]
        return BinaryNode(tag="receipt", attrs=attrs, content=None)

    items = [BinaryNode(tag="item", attrs={"id": mid}) for mid in message_ids]
    return BinaryNode(tag="receipt", attrs=attrs, content=items)

