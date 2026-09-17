"""Message Secret framework for encrypted comments, reactions, poll votes, and bot messages."""

from __future__ import annotations

import os
from typing import Any

from waton.core.jid import jid_normalized_user
from waton.protocol.protobuf.wire import (
    encode_bool,
    encode_len_delimited,
    encode_string,
    iter_fields,
)
from waton.utils.crypto import aes_gcm_decrypt, aes_gcm_encrypt, hkdf


def apply_bot_message_hkdf(message_secret: bytes) -> bytes:
    """Derive secret for Meta AI bot message."""
    return hkdf(message_secret, 32, salt=b"", info=b"Bot Message")


def generate_msg_secret_key(
    modification_type: str,
    modification_sender_jid: str,
    orig_msg_id: str,
    orig_msg_sender_jid: str,
    orig_msg_secret: bytes,
) -> tuple[bytes, bytes]:
    """Derive encryption key and additional authenticated data for message modifications."""
    orig_sender = jid_normalized_user(orig_msg_sender_jid)
    mod_sender = jid_normalized_user(modification_sender_jid)

    use_case_secret = (orig_msg_id + orig_sender + mod_sender + modification_type).encode("utf-8")
    secret_key = hkdf(orig_msg_secret, 32, salt=b"", info=use_case_secret)

    additional_data = b""
    if modification_type in {"Poll Vote", "Event Response", ""}:
        additional_data = f"{orig_msg_id}\x00{mod_sender}".encode("utf-8")

    return secret_key, additional_data


def encrypt_comment(
    *,
    comment_payload: bytes,
    root_message_id: str,
    root_sender_jid: str,
    root_chat_jid: str,
    own_jid: str,
    message_secret: bytes,
) -> dict[str, Any]:
    """Encrypt a comment/reply in community announcement groups."""
    secret_key, additional_data = generate_msg_secret_key(
        modification_type="Enc Comment",
        modification_sender_jid=own_jid,
        orig_msg_id=root_message_id,
        orig_msg_sender_jid=root_sender_jid,
        orig_msg_secret=message_secret,
    )

    iv = os.urandom(12)
    ciphertext = aes_gcm_encrypt(comment_payload, secret_key, iv, additional_data)

    target_key = b"".join(
        (
            encode_string(1, root_chat_jid),
            encode_bool(2, False),
            encode_string(3, root_message_id),
            encode_string(4, jid_normalized_user(root_sender_jid)),
        )
    )

    enc_comment = b"".join(
        (
            encode_len_delimited(1, target_key),
            encode_len_delimited(2, ciphertext),
            encode_len_delimited(3, iv),
        )
    )

    return {
        "enc_comment_bytes": enc_comment,
        "ciphertext": ciphertext,
        "iv": iv,
        "target_key": target_key,
    }


def decrypt_comment(
    *,
    ciphertext: bytes,
    iv: bytes,
    root_message_id: str,
    root_sender_jid: str,
    comment_sender_jid: str,
    message_secret: bytes,
) -> bytes:
    """Decrypt an encrypted comment payload."""
    secret_key, additional_data = generate_msg_secret_key(
        modification_type="Enc Comment",
        modification_sender_jid=comment_sender_jid,
        orig_msg_id=root_message_id,
        orig_msg_sender_jid=root_sender_jid,
        orig_msg_secret=message_secret,
    )

    return aes_gcm_decrypt(ciphertext, secret_key, iv, additional_data)


def encrypt_reaction(
    *,
    reaction_payload: bytes,
    target_message_id: str,
    target_sender_jid: str,
    target_chat_jid: str,
    own_jid: str,
    message_secret: bytes,
) -> dict[str, Any]:
    """Encrypt a reaction in community announcement groups."""
    secret_key, additional_data = generate_msg_secret_key(
        modification_type="Enc Reaction",
        modification_sender_jid=own_jid,
        orig_msg_id=target_message_id,
        orig_msg_sender_jid=target_sender_jid,
        orig_msg_secret=message_secret,
    )

    iv = os.urandom(12)
    ciphertext = aes_gcm_encrypt(reaction_payload, secret_key, iv, additional_data)

    target_key = b"".join(
        (
            encode_string(1, target_chat_jid),
            encode_bool(2, False),
            encode_string(3, target_message_id),
            encode_string(4, jid_normalized_user(target_sender_jid)),
        )
    )

    enc_reaction = b"".join(
        (
            encode_len_delimited(1, target_key),
            encode_len_delimited(2, ciphertext),
            encode_len_delimited(3, iv),
        )
    )

    return {
        "enc_reaction_bytes": enc_reaction,
        "ciphertext": ciphertext,
        "iv": iv,
        "target_key": target_key,
    }


def decrypt_reaction(
    *,
    ciphertext: bytes,
    iv: bytes,
    target_message_id: str,
    target_sender_jid: str,
    reactor_jid: str,
    message_secret: bytes,
) -> bytes:
    """Decrypt an encrypted reaction payload."""
    secret_key, additional_data = generate_msg_secret_key(
        modification_type="Enc Reaction",
        modification_sender_jid=reactor_jid,
        orig_msg_id=target_message_id,
        orig_msg_sender_jid=target_sender_jid,
        orig_msg_secret=message_secret,
    )

    return aes_gcm_decrypt(ciphertext, secret_key, iv, additional_data)
