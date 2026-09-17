from __future__ import annotations

import asyncio
import base64
import os
import pytest

from waton.client.chats import ChatsAPI
from waton.client.client import WAClient
from waton.client.event_pipeline import EventPipeline
from waton.client.media import MediaManager
from waton.client.messages_recv import (
    build_call_reject_node,
    build_retry_keys_node,
    build_retry_receipt_node,
    classify_incoming_node,
    decode_presence_node,
    normalize_incoming_node,
)
from waton.client.presence import PresenceAPI
from waton.protocol.binary_node import BinaryNode
from waton.utils.auth import init_auth_creds
from waton.utils.crypto import (
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_encrypt,
    bytes_to_crockford,
    derive_pairing_code_key,
    generate_keypair,
    hkdf,
)
from waton.utils.protocol_message import decrypt_enc_reaction


class _DummyStorage:
    def __init__(self) -> None:
        self.creds = init_auth_creds()

    async def get_creds(self) -> Any:
        return self.creds

    async def save_creds(self, creds: Any) -> None:
        self.creds = creds


class _FakeClient:
    def __init__(self) -> None:
        self.sent: list[BinaryNode] = []
        self.queries: list[BinaryNode] = []
        self.creds = init_auth_creds()
        self.storage = _DummyStorage()
        self.config = {"frame_timeout": 5.0}


    async def send_node(self, node: BinaryNode) -> None:
        self.sent.append(node)

    async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
        self.queries.append(node)
        return BinaryNode(tag="iq", attrs={"type": "result"})

    def _generate_message_tag(self) -> str:
        return os.urandom(6).hex()


def test_crockford_and_pairing_crypto() -> None:
    data = bytes([0x00, 0x01, 0x02, 0x03, 0x04])
    code = bytes_to_crockford(data)
    assert len(code) == 8
    assert all(c in "123456789ABCDEFGHJKLMNPQRSTVWXYZ" for c in code)

    salt = os.urandom(32)
    key = derive_pairing_code_key(code, salt)
    assert len(key) == 32

    iv = os.urandom(16)
    plaintext = b"test-secret-payload"
    ciphered = aes_ctr_encrypt(plaintext, key, iv)
    assert ciphered != plaintext
    decrypted = aes_ctr_decrypt(ciphered, key, iv)
    assert decrypted == plaintext


def test_decrypt_enc_reaction() -> None:
    message_secret = os.urandom(32)
    target_id = "MSG12345"
    creator_jid = "creator@s.whatsapp.net"
    actor_jid = "reactor@s.whatsapp.net"

    dec_key = hkdf(
        message_secret,
        32,
        info=(target_id + creator_jid + actor_jid + "Enc Reaction").encode("utf-8"),
        salt=b"",
    )

    emoji = "🔥"
    emoji_bytes = emoji.encode("utf-8")
    reaction_payload = (
        b"\x12" + bytes([len(emoji_bytes)]) + emoji_bytes
        + b"\x20\xe8\x07"
    )

    iv = os.urandom(12)
    ciphertext = aes_encrypt(reaction_payload, dec_key, iv, b"")

    res = decrypt_enc_reaction(
        enc_payload_b64=base64.b64encode(ciphertext).decode("ascii"),
        enc_iv_b64=base64.b64encode(iv).decode("ascii"),
        target_message_id=target_id,
        target_creator_jid=creator_jid,
        reactor_jid=actor_jid,
        message_secret=message_secret,
    )

    assert res["text"] == "🔥"
    assert res["target_message_id"] == target_id
    assert res["sender_jid"] == actor_jid
    assert res["sender_timestamp_ms"] == 1000


@pytest.mark.asyncio
async def test_presence_chatstate_api() -> None:
    client = _FakeClient()
    presence_api = PresenceAPI(client)  # type: ignore[arg-type]

    await presence_api.send_chat_composing("target@s.whatsapp.net")
    node = client.sent[-1]
    assert node.tag == "chatstate"
    assert node.attrs["to"] == "target@s.whatsapp.net"
    assert len(node.content) == 1
    assert node.content[0].tag == "composing"

    await presence_api.send_chat_recording("target@s.whatsapp.net")
    node = client.sent[-1]
    assert node.tag == "chatstate"
    assert node.content[0].tag == "composing"
    assert node.content[0].attrs.get("media") == "audio"

    await presence_api.send_chat_paused("target@s.whatsapp.net")
    node = client.sent[-1]
    assert node.tag == "chatstate"
    assert node.content[0].tag == "paused"


@pytest.mark.asyncio
async def test_chats_api_extended() -> None:
    client = _FakeClient()
    api = ChatsAPI(client)  # type: ignore[arg-type]

    await api.send_chat_presence("chat@s.whatsapp.net", state="composing", media="audio")
    assert client.sent[-1].tag == "chatstate"
    assert client.sent[-1].content[0].attrs["media"] == "audio"

    await api.update_profile_picture("target@s.whatsapp.net", b"fake-jpg-data")
    assert client.queries[-1].attrs["xmlns"] == "w:profile:picture"
    assert client.queries[-1].attrs["target"] == "target@s.whatsapp.net"
    assert client.queries[-1].content[0].tag == "picture"
    assert client.queries[-1].content[0].content == b"fake-jpg-data"

    await api.remove_profile_picture("target@s.whatsapp.net")
    assert client.queries[-1].content[0].attrs.get("delete") == "true"

    await api.update_block_status("spammer@s.whatsapp.net", "block")
    assert client.queries[-1].attrs["xmlns"] == "blocklist"
    assert client.queries[-1].content[0].attrs["action"] == "block"
    assert client.queries[-1].content[0].attrs["jid"] == "spammer@s.whatsapp.net"

    await api.update_online_privacy("all")
    assert client.queries[-1].attrs["xmlns"] == "privacy"
    assert client.queries[-1].content[0].content[0].attrs["name"] == "online"

    await api.update_profile_picture_privacy("contacts")
    assert client.queries[-1].content[0].content[0].attrs["name"] == "profile"

    await api.set_default_disappearing_mode(86400)
    assert client.queries[-1].attrs["xmlns"] == "disappearing_mode"
    assert client.queries[-1].content[0].attrs["duration"] == "86400"


def test_decode_chatstate_presence_node() -> None:
    chatstate_node = BinaryNode(
        tag="chatstate",
        attrs={"from": "alice@s.whatsapp.net", "participant": "alice@s.whatsapp.net"},
        content=[BinaryNode(tag="composing", attrs={"media": "audio"})],
    )
    assert classify_incoming_node(chatstate_node) == "presence"

    decoded = decode_presence_node(chatstate_node)
    assert decoded["type"] == "presence.update"
    presence = decoded["presence"]["presences"]["alice@s.whatsapp.net"]
    assert presence["last_known_presence"] == "recording"
    assert presence["media"] == "audio"

    presence_node = BinaryNode(
        tag="presence",
        attrs={"from": "bob@s.whatsapp.net", "type": "available", "last": "1720000000"},
    )
    decoded_p = decode_presence_node(presence_node)
    assert decoded_p["presence"]["presences"]["bob@s.whatsapp.net"]["last_known_presence"] == "available"
    assert decoded_p["presence"]["presences"]["bob@s.whatsapp.net"]["last_seen"] == 1720000000


def test_build_retry_receipt_node_with_key_bundle() -> None:
    node = BinaryNode(tag="message", attrs={"id": "MSG999", "from": "peer@s.whatsapp.net"})

    receipt_1 = build_retry_receipt_node(node, retry_count=1, registration_id=12345)
    assert receipt_1.tag == "receipt"
    assert len(receipt_1.content) == 2
    assert receipt_1.content[0].tag == "retry"
    assert receipt_1.content[0].attrs["count"] == "1"
    assert receipt_1.content[1].tag == "registration"
    assert receipt_1.content[1].content == (12345).to_bytes(4, "big")

    keys_node = build_retry_keys_node(
        identity_key_public=b"id-key-32-bytes-----------------",
        signed_prekey_public=b"spk-32-bytes--------------------",
        signed_prekey_id=5,
        signed_prekey_signature=b"sig-64-bytes----------------------------------------------------",
        prekey_public=b"pk-32-bytes---------------------",
        prekey_id=10,
        device_identity=b"dev-identity-bytes",
    )
    assert keys_node.tag == "keys"
    assert any(c.tag == "identity" for c in keys_node.content)
    assert any(c.tag == "skey" for c in keys_node.content)
    assert any(c.tag == "key" for c in keys_node.content)
    assert any(c.tag == "device-identity" for c in keys_node.content)

    receipt_2 = build_retry_receipt_node(
        node,
        retry_count=2,
        registration_id=12345,
        keys_node=keys_node,
    )
    assert len(receipt_2.content) == 3
    assert receipt_2.content[2].tag == "keys"


@pytest.mark.asyncio
async def test_request_pairing_code_and_companion_reg() -> None:
    client = WAClient(_DummyStorage())
    client.is_connected = True
    client.noise = type("FakeNoise", (), {"encode_frame": lambda self, p: p})()
    sent_nodes: list[BinaryNode] = []

    class _MockWs:
        async def send(self, f: Any) -> None:
            sent_nodes.append(f)

    client.ws = _MockWs()


    code = await client.request_pairing_code("628123456789", custom_pairing_code="ABCD1234")
    assert code == "ABCD-1234"
    assert client.creds.pairing_code == "ABCD1234"
    assert client.creds.me["id"] == "628123456789@s.whatsapp.net"

    assert len(sent_nodes) > 0

    await client.reject_call(call_id="call-001", call_from="caller@s.whatsapp.net")
    assert len(sent_nodes) == 2



@pytest.mark.asyncio
async def test_media_retry_receipt_and_decrypt() -> None:
    client = _FakeClient()
    media_mgr = MediaManager(client)  # type: ignore[arg-type]

    media_key = os.urandom(32)
    message_id = "MSG_MEDIA_001"
    chat_jid = "chat@s.whatsapp.net"

    ciphertext, iv = media_mgr.encrypt_media_retry_receipt(message_id, media_key)
    assert len(ciphertext) > 0
    assert len(iv) == 12

    await media_mgr.send_media_retry_receipt(
        message_id=message_id,
        chat_jid=chat_jid,
        media_key=media_key,
    )
    sent = client.sent[-1]
    assert sent.tag == "receipt"
    assert sent.attrs["type"] == "server-error"
    assert sent.content[0].tag == "encrypt"
    assert sent.content[1].tag == "rmr"

    retry_key = hkdf(media_key, 32, salt=b"", info=b"WhatsApp Media Retry Notification")
    p_id = message_id.encode("utf-8")
    p_path = b"/v/t62.7118-24/test.enc"
    notif_plain = (
        bytes([1 << 3 | 2, len(p_id)]) + p_id
        + bytes([2 << 3 | 2, len(p_path)]) + p_path
        + bytes([3 << 3 | 0, 1])
    )
    notif_iv = os.urandom(12)
    notif_cipher = aes_encrypt(notif_plain, retry_key, notif_iv, aad=message_id.encode("utf-8"))


    decrypted = MediaManager.decrypt_media_retry_notification(
        media_key=media_key,
        ciphertext=notif_cipher,
        iv=notif_iv,
        message_id=message_id,
    )
    assert decrypted["stanza_id"] == "MSG_MEDIA_001"
    assert decrypted["direct_path"] == "/v/t62.7118-24/test.enc"
    assert decrypted["result"] == 1


@pytest.mark.asyncio
async def test_event_pipeline_batching_and_flush() -> None:
    saved = []
    emitted = []

    async def _save(e):
        saved.append(e["id"])

    async def _emit(e):
        emitted.append(e["id"])

    pipeline = EventPipeline(save_fn=_save, emit_fn=_emit, batch_size=3)

    for i in range(5):
        pipeline.enqueue({"id": f"event_{i}"})

    flushed = await pipeline.flush()
    assert flushed == 5
    assert saved == [f"event_{i}" for i in range(5)]
    assert emitted == [f"event_{i}" for i in range(5)]
