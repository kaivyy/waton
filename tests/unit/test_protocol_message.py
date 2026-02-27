from __future__ import annotations

import base64

from waton.protocol.protobuf.wire import _encode_len_delimited, _encode_varint_field
from waton.utils.crypto import aes_encrypt, hmac_sha256
from waton.utils.protocol_message import decrypt_event_response, decrypt_poll_vote


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


def test_decrypt_poll_vote_roundtrip() -> None:
    poll_message_id = "poll-mid"
    creator_jid = "creator@s.whatsapp.net"
    voter_jid = "voter@s.whatsapp.net"
    secret = bytes(range(32))
    iv = bytes(range(12))

    plaintext = _encode_len_delimited(1, b"opt-a") + _encode_len_delimited(1, b"opt-b")
    key = _derive_message_addon_key(
        addon_label="Poll Vote",
        message_id=poll_message_id,
        creator_jid=creator_jid,
        actor_jid=voter_jid,
        message_secret=secret,
    )
    aad = f"{poll_message_id}\x00{voter_jid}".encode("utf-8")
    ciphertext = aes_encrypt(plaintext, key, iv, aad)

    out = decrypt_poll_vote(
        enc_payload_b64=base64.b64encode(ciphertext).decode("ascii"),
        enc_iv_b64=base64.b64encode(iv).decode("ascii"),
        poll_message_id=poll_message_id,
        poll_creator_jid=creator_jid,
        voter_jid=voter_jid,
        poll_enc_key=secret,
    )

    assert out["selected_options_b64"] == [
        base64.b64encode(b"opt-a").decode("ascii"),
        base64.b64encode(b"opt-b").decode("ascii"),
    ]
    assert out["sender_jid"] == voter_jid


def test_decrypt_event_response_roundtrip() -> None:
    event_message_id = "event-mid"
    creator_jid = "creator@s.whatsapp.net"
    responder_jid = "responder@s.whatsapp.net"
    secret = bytes(range(32, 64))
    iv = bytes(range(16, 28))

    plaintext = (
        _encode_varint_field(1, 1)  # GOING
        + _encode_varint_field(2, 123456789)
        + _encode_varint_field(3, 2)
    )
    key = _derive_message_addon_key(
        addon_label="Event Response",
        message_id=event_message_id,
        creator_jid=creator_jid,
        actor_jid=responder_jid,
        message_secret=secret,
    )
    aad = f"{event_message_id}\x00{responder_jid}".encode("utf-8")
    ciphertext = aes_encrypt(plaintext, key, iv, aad)

    out = decrypt_event_response(
        enc_payload_b64=base64.b64encode(ciphertext).decode("ascii"),
        enc_iv_b64=base64.b64encode(iv).decode("ascii"),
        event_message_id=event_message_id,
        event_creator_jid=creator_jid,
        responder_jid=responder_jid,
        event_enc_key=secret,
    )

    assert out["response_type"] == 1
    assert out["timestamp_ms"] == 123456789
    assert out["extra_guest_count"] == 2
    assert out["sender_jid"] == responder_jid
