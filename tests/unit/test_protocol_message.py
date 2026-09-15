from __future__ import annotations

import base64

from waton.protocol.protobuf.wire import _encode_len_delimited, _encode_varint_field
from waton.utils.crypto import aes_encrypt, hmac_sha256
from waton.utils.protocol_message import (
    _derive_message_addon_key,
    decrypt_event_response,
    decrypt_poll_vote,
)


def test_derive_addon_keys_matches_baileys_and_rfc5869() -> None:
    import hashlib
    import hmac


    message_secret = b"\x01" * 32
    message_id = "msg123"
    creator_jid = "creator@s.whatsapp.net"
    actor_jid = "actor@s.whatsapp.net"
    addon_label = "Poll Vote"

    sign = b"".join(
        (
            message_id.encode("utf-8"),
            creator_jid.encode("utf-8"),
            actor_jid.encode("utf-8"),
            addon_label.encode("utf-8"),
            b"\x01",
        )
    )

    # In RFC 5869 / Baileys: key0 = HMAC(key=zeros, data=message_secret), decKey = HMAC(key=key0, data=sign)
    expected_key0 = hmac.new(bytes(32), message_secret, hashlib.sha256).digest()
    expected_deckey = hmac.new(expected_key0, sign, hashlib.sha256).digest()

    actual_deckey = _derive_message_addon_key(
        addon_label=addon_label,
        message_id=message_id,
        creator_jid=creator_jid,
        actor_jid=actor_jid,
        message_secret=message_secret,
    )
    assert actual_deckey == expected_deckey




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
    aad = f"{poll_message_id}\x00{voter_jid}".encode()
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
    aad = f"{event_message_id}\x00{responder_jid}".encode()
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
