"""Chat JID helper functions."""

from __future__ import annotations

from waton.core.jid import is_jid_group, is_jid_user, jid_decode, jid_encode


def is_group_chat(jid: str) -> bool:
    return is_jid_group(jid)


def is_private_chat(jid: str) -> bool:
    return is_jid_user(jid)


def normalize_chat_jid(jid: str) -> str:
    decoded = jid_decode(jid)
    if decoded is None:
        return jid
    return jid_encode(decoded.user, decoded.server)
