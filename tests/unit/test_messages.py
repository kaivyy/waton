import asyncio
from base64 import b64encode
import logging
from typing import Any

import pytest

from waton.client.messages import MessagesAPI
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import wa_pb2
from waton.protocol.protobuf.wire import _encode_len_delimited, _encode_string, _encode_varint_field, _iter_fields
from waton.utils.media_utils import derive_media_keys
from waton.utils.process_message import process_incoming_message
from waton.utils.auth import init_auth_creds
from waton.client.messages import _write_random_pad_max16, _unpad_random_max16
from waton.utils.crypto import aes_encrypt, hmac_sha256


def test_padding_unpadding():
    msg = b"\x01\x02\x03hello"
    padded = _write_random_pad_max16(msg)
    assert len(padded) > len(msg)
    assert len(padded) <= len(msg) + 16
    unpadded = _unpad_random_max16(padded)
    assert unpadded == msg

    # invalid padding scenarios
    assert _unpad_random_max16(b"") == b""
    assert _unpad_random_max16(b"\x00") == b"\x00"
    assert _unpad_random_max16(b"hello\x06\x06\x06") == b"hello\x06\x06\x06" # 3 bytes instead of 6


class _FakeClient:
    def __init__(self) -> None:
        self.sent: list[BinaryNode] = []
        self.storage = _MemoryStorage()
        self.creds = init_auth_creds()
        self.creds.me = {"id": "555@s.whatsapp.net"}
        self.creds.account = {
            "details": b64encode(b"d").decode("utf-8"),
            "account_signature_key": b64encode(b"k").decode("utf-8"),
            "account_signature": b64encode(b"a").decode("utf-8"),
            "device_signature": b64encode(b"s").decode("utf-8"),
        }
        self._tag_counter = 0

    def _generate_message_tag(self) -> str:
        self._tag_counter += 1
        return str(self._tag_counter)

    async def send_node(self, node: BinaryNode) -> None:
        self.sent.append(node)

    async def query(self, node: BinaryNode, timeout: float | None = None) -> BinaryNode:
        xmlns = node.attrs.get("xmlns", "")

        # Handle usync device query
        if xmlns == "usync":
            return self._handle_usync_query(node)

        # Handle encrypt key query
        return self._handle_encrypt_query(node)

    def _handle_usync_query(self, node: BinaryNode) -> BinaryNode:
        """Return mock device list: each user has device 0 and device 1."""
        usync_node = node.content[0]
        list_node = None
        for child in usync_node.content:
            if child.tag == "list":
                list_node = child
                break

        user_results = []
        if list_node and isinstance(list_node.content, list):
            for user_node in list_node.content:
                jid = user_node.attrs.get("jid", "")
                user = jid.split("@")[0] if "@" in jid else jid
                server = jid.split("@")[1] if "@" in jid else "s.whatsapp.net"
                user_results.append(
                    BinaryNode(
                        tag="user",
                        attrs={"jid": jid},
                        content=[
                            BinaryNode(
                                tag="devices",
                                attrs={},
                                content=[
                                    BinaryNode(
                                        tag="device-list",
                                        attrs={},
                                        content=[
                                            BinaryNode(tag="device", attrs={"id": "0"}, content=None),
                                            BinaryNode(tag="device", attrs={"id": "1", "key-index": "1"}, content=None),
                                        ],
                                    )
                                ],
                            )
                        ],
                    )
                )

        return BinaryNode(
            tag="iq",
            attrs={"type": "result"},
            content=[
                BinaryNode(
                    tag="usync",
                    attrs={},
                    content=[
                        BinaryNode(tag="list", attrs={}, content=user_results),
                    ],
                )
            ],
        )

    def _handle_encrypt_query(self, node: BinaryNode) -> BinaryNode:
        """Return mock prekey bundle for each user in the encrypt query."""
        users: list[BinaryNode] = []
        key_node = node.content[0]
        assert isinstance(key_node.content, list)
        for user in key_node.content:
            jid = user.attrs["jid"]
            users.append(
                BinaryNode(
                    tag="user",
                    attrs={"jid": jid},
                    content=[
                        BinaryNode(tag="registration", attrs={}, content=(1).to_bytes(4, "big")),
                        BinaryNode(tag="identity", attrs={}, content=b"i" * 32),
                        BinaryNode(
                            tag="skey",
                            attrs={},
                            content=[
                                BinaryNode(tag="id", attrs={}, content=(2).to_bytes(3, "big")),
                                BinaryNode(tag="value", attrs={}, content=b"s" * 32),
                                BinaryNode(tag="signature", attrs={}, content=b"g" * 64),
                            ],
                        ),
                        BinaryNode(
                            tag="key",
                            attrs={},
                            content=[
                                BinaryNode(tag="id", attrs={}, content=(3).to_bytes(3, "big")),
                                BinaryNode(tag="value", attrs={}, content=b"p" * 32),
                            ],
                        ),
                    ],
                )
            )

        return BinaryNode(tag="iq", attrs={"type": "result"}, content=[BinaryNode(tag="list", attrs={}, content=users)])


class _MemoryStorage:
    def __init__(self) -> None:
        self.creds = None
        self.sessions: dict[str, bytes] = {}
        self.prekeys: dict[int, bytes] = {}
        self.sender_keys: dict[tuple[str, str], bytes] = {}

    async def get_creds(self):
        return self.creds

    async def save_creds(self, creds):
        self.creds = creds

    async def get_session(self, jid: str):
        return self.sessions.get(jid)

    async def save_session(self, jid: str, data: bytes):
        self.sessions[jid] = data

    async def get_prekey(self, key_id: int):
        return self.prekeys.get(key_id)

    async def save_prekey(self, key_id: int, data: bytes):
        self.prekeys[key_id] = data

    async def get_sender_key(self, group_jid: str, sender_jid: str):
        return self.sender_keys.get((group_jid, sender_jid))

    async def save_sender_key(self, group_jid: str, sender_jid: str, data: bytes):
        self.sender_keys[(group_jid, sender_jid)] = data


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _derive_addon_key(
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


def test_send_text_builds_message_node(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_process(
        session: bytes | None,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        remote_registration_id: int,
        remote_identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> bytes:
        assert registration_id > 0
        assert remote_name in {"123", "555"}
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session.startswith(b"session-for-")
        assert registration_id > 0
        assert plaintext
        return "msg", b"cipher-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8"), session

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        message_id = await api.send_text("123@s.whatsapp.net", "hello")
        assert message_id
        assert len(client.sent) == 1

        message = client.sent[0]
        assert message.tag == "message"
        assert message.attrs["to"] == "123@s.whatsapp.net"
        assert message.attrs["type"] == "text"
        assert isinstance(message.content, list)
        participants = message.content[0]
        assert participants.tag == "participants"
        assert isinstance(participants.content, list)

        # Multi-device: expect device-specific JIDs
        # target: 123:0, 123:1; self: 555:1 (555:0 is filtered out)
        participant_jids = [p.attrs["jid"] for p in participants.content]
        assert "123:0@s.whatsapp.net" in participant_jids
        assert "123:1@s.whatsapp.net" in participant_jids
        assert "555:1@s.whatsapp.net" in participant_jids
        assert "555:0@s.whatsapp.net" not in participant_jids
        assert len(participant_jids) == 3

    _run(_case())


def test_send_reaction_and_receipt() -> None:
    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        reaction_id = await api.send_reaction("123@s.whatsapp.net", "mid123", "👍")
        assert reaction_id.startswith("reaction_")
        await api.send_receipt(
            jid="123@s.whatsapp.net",
            participant="456@s.whatsapp.net",
            message_ids=["mid1", "mid2"],
            receipt_type="read",
        )

        reaction_node = client.sent[0]
        receipt_node = client.sent[1]
        assert reaction_node.attrs["type"] == "reaction"
        assert receipt_node.tag == "receipt"
        assert receipt_node.attrs["participant"] == "456@s.whatsapp.net"
        assert len(receipt_node.content) == 2

    _run(_case())


def test_send_document_builds_message_node(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_plaintexts: list[bytes] = []

    def _fake_process(
        session: bytes | None,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        remote_registration_id: int,
        remote_identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> bytes:
        assert registration_id > 0
        assert remote_name in {"123", "555"}
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session.startswith(b"session-for-")
        captured_plaintexts.append(plaintext)
        return "msg", b"cipher-document-" + remote_name.encode("utf-8"), session

    async def _fake_encrypt_and_upload(self: object, media_type: str, raw_media: bytes) -> dict[str, str | bytes]:
        del self
        assert media_type == "document"
        assert raw_media == b"pdf-bytes"
        return {
            "url": "https://media.local/doc",
            "mediaKey": b"k" * 32,
            "fileSha256": b"h" * 32,
            "fileEncSha256": b"e" * 32,
            "fileLength": len(raw_media),
            "mediaType": "document",
        }

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)
    monkeypatch.setattr("waton.client.media.MediaManager.encrypt_and_upload", _fake_encrypt_and_upload)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        message_id = await api.send_document(
            "123@s.whatsapp.net",
            b"pdf-bytes",
            file_name="invoice.pdf",
            caption="doc caption",
        )
        assert message_id
        assert len(client.sent) == 1
        message = client.sent[0]
        assert message.tag == "message"
        assert message.attrs["type"] == "document"
        assert isinstance(message.content, list)
        participants = message.content[0]
        assert participants.tag == "participants"
        assert isinstance(participants.content, list)
        assert len(participants.content) == 3
        assert captured_plaintexts

        unpadded = [_unpad_random_max16(payload) for payload in captured_plaintexts]
        assert any(any(field == 7 for field, _, _ in _iter_fields(payload)) for payload in unpadded)

    _run(_case())


def test_send_location_builds_message_node(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_plaintexts: list[bytes] = []

    def _fake_process(
        session: bytes | None,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        remote_registration_id: int,
        remote_identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> bytes:
        assert registration_id > 0
        assert remote_name in {"123", "555"}
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session.startswith(b"session-for-")
        captured_plaintexts.append(plaintext)
        return "msg", b"cipher-location-" + remote_name.encode("utf-8"), session

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        message_id = await api.send_location(
            "123@s.whatsapp.net",
            latitude=-6.2,
            longitude=106.8,
            name="Jakarta",
            address="DKI",
        )
        assert message_id
        assert len(client.sent) == 1
        message = client.sent[0]
        assert message.tag == "message"
        assert message.attrs["type"] == "location"
        assert isinstance(message.content, list)
        participants = message.content[0]
        assert participants.tag == "participants"
        assert isinstance(participants.content, list)
        assert len(participants.content) == 3
        assert captured_plaintexts

        unpadded = [_unpad_random_max16(payload) for payload in captured_plaintexts]
        assert any(any(field == 5 for field, _, _ in _iter_fields(payload)) for payload in unpadded)

    _run(_case())


def test_send_audio_builds_message_node(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_plaintexts: list[bytes] = []

    def _fake_process(
        session: bytes | None,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        remote_registration_id: int,
        remote_identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> bytes:
        assert registration_id > 0
        assert remote_name in {"123", "555"}
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session.startswith(b"session-for-")
        captured_plaintexts.append(plaintext)
        return "msg", b"cipher-audio-" + remote_name.encode("utf-8"), session

    async def _fake_encrypt_and_upload(self: object, media_type: str, raw_media: bytes) -> dict[str, str | bytes]:
        del self
        assert media_type == "audio"
        assert raw_media == b"audio-bytes"
        return {
            "url": "https://media.local/audio",
            "mediaKey": b"a" * 32,
            "fileSha256": b"h" * 32,
            "fileEncSha256": b"e" * 32,
            "fileLength": len(raw_media),
            "mediaType": "audio",
        }

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)
    monkeypatch.setattr("waton.client.media.MediaManager.encrypt_and_upload", _fake_encrypt_and_upload)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        message_id = await api.send_audio("123@s.whatsapp.net", b"audio-bytes", seconds=7, ptt=True)
        assert message_id
        message = client.sent[0]
        assert message.attrs["type"] == "audio"
        unpadded = [_unpad_random_max16(payload) for payload in captured_plaintexts]
        assert any(any(field == 8 for field, _, _ in _iter_fields(payload)) for payload in unpadded)

    _run(_case())


def test_send_video_builds_message_node(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_plaintexts: list[bytes] = []

    def _fake_process(
        session: bytes | None,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        remote_registration_id: int,
        remote_identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> bytes:
        assert registration_id > 0
        assert remote_name in {"123", "555"}
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session.startswith(b"session-for-")
        captured_plaintexts.append(plaintext)
        return "msg", b"cipher-video-" + remote_name.encode("utf-8"), session

    async def _fake_encrypt_and_upload(self: object, media_type: str, raw_media: bytes) -> dict[str, str | bytes]:
        del self
        assert media_type == "video"
        assert raw_media == b"video-bytes"
        return {
            "url": "https://media.local/video",
            "mediaKey": b"v" * 32,
            "fileSha256": b"h" * 32,
            "fileEncSha256": b"e" * 32,
            "fileLength": len(raw_media),
            "mediaType": "video",
        }

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)
    monkeypatch.setattr("waton.client.media.MediaManager.encrypt_and_upload", _fake_encrypt_and_upload)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        message_id = await api.send_video(
            "123@s.whatsapp.net",
            b"video-bytes",
            caption="clip",
            seconds=5,
            height=720,
            width=1280,
        )
        assert message_id
        message = client.sent[0]
        assert message.attrs["type"] == "video"
        unpadded = [_unpad_random_max16(payload) for payload in captured_plaintexts]
        assert any(any(field == 9 for field, _, _ in _iter_fields(payload)) for payload in unpadded)

    _run(_case())


def test_send_sticker_builds_message_node(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_plaintexts: list[bytes] = []

    def _fake_process(
        session: bytes | None,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        remote_registration_id: int,
        remote_identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> bytes:
        assert registration_id > 0
        assert remote_name in {"123", "555"}
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session.startswith(b"session-for-")
        captured_plaintexts.append(plaintext)
        return "msg", b"cipher-sticker-" + remote_name.encode("utf-8"), session

    async def _fake_encrypt_and_upload(self: object, media_type: str, raw_media: bytes) -> dict[str, str | bytes]:
        del self
        assert media_type == "sticker"
        assert raw_media == b"sticker-bytes"
        return {
            "url": "https://media.local/sticker",
            "mediaKey": b"s" * 32,
            "fileSha256": b"h" * 32,
            "fileEncSha256": b"e" * 32,
            "fileLength": len(raw_media),
            "mediaType": "sticker",
        }

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)
    monkeypatch.setattr("waton.client.media.MediaManager.encrypt_and_upload", _fake_encrypt_and_upload)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        message_id = await api.send_sticker("123@s.whatsapp.net", b"sticker-bytes", height=512, width=512)
        assert message_id
        message = client.sent[0]
        assert message.attrs["type"] == "sticker"
        unpadded = [_unpad_random_max16(payload) for payload in captured_plaintexts]
        assert any(any(field == 26 for field, _, _ in _iter_fields(payload)) for payload in unpadded)

    _run(_case())


def test_send_contact_builds_message_node(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_plaintexts: list[bytes] = []

    def _fake_process(
        session: bytes | None,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        remote_registration_id: int,
        remote_identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> bytes:
        assert registration_id > 0
        assert remote_name in {"123", "555"}
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session.startswith(b"session-for-")
        captured_plaintexts.append(plaintext)
        return "msg", b"cipher-contact-" + remote_name.encode("utf-8"), session

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        message_id = await api.send_contact(
            "123@s.whatsapp.net",
            display_name="Arvy",
            vcard="BEGIN:VCARD\nFN:Arvy\nEND:VCARD",
        )
        assert message_id
        message = client.sent[0]
        assert message.attrs["type"] == "contact"
        unpadded = [_unpad_random_max16(payload) for payload in captured_plaintexts]
        assert any(any(field == 4 for field, _, _ in _iter_fields(payload)) for payload in unpadded)

    _run(_case())


def test_send_poll_creation_builds_message_node(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_plaintexts: list[bytes] = []

    def _fake_process(
        session: bytes | None,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        remote_registration_id: int,
        remote_identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> bytes:
        assert registration_id > 0
        assert remote_name in {"123", "555"}
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session.startswith(b"session-for-")
        captured_plaintexts.append(plaintext)
        return "msg", b"cipher-poll-" + remote_name.encode("utf-8"), session

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        message_id = await api.send_poll_creation(
            "123@s.whatsapp.net",
            name="Lunch?",
            options=["Nasi", "Mie"],
            selectable_options_count=1,
        )
        assert message_id
        message = client.sent[0]
        assert message.attrs["type"] == "poll"
        unpadded = [_unpad_random_max16(payload) for payload in captured_plaintexts]
        assert any(any(field == 49 for field, _, _ in _iter_fields(payload)) for payload in unpadded)

    _run(_case())


def test_process_incoming_message_extracts_text() -> None:
    async def _case() -> None:
        msg = wa_pb2.Message()
        msg.conversation = "incoming hello"
        node = BinaryNode(
            tag="message",
            attrs={"id": "m1", "from": "999@s.whatsapp.net", "type": "text"},
            content=msg.SerializeToString(),
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.id == "m1"
        assert parsed.text == "incoming hello"
        assert parsed.from_jid == "999@s.whatsapp.net"
    _run(_case())


def test_process_incoming_message_extracts_reaction() -> None:
    async def _case() -> None:
        msg = wa_pb2.Message()
        msg.reactionMessage.key.id = "target-mid"
        msg.reactionMessage.key.remoteJid = "999@s.whatsapp.net"
        msg.reactionMessage.text = "👍"
        node = BinaryNode(
            tag="message",
            attrs={"id": "m2", "from": "999@s.whatsapp.net", "type": "reaction"},
            content=msg.SerializeToString(),
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.id == "m2"
        assert parsed.reaction == "👍"
        assert parsed.text is None
        assert parsed.message_type == "reaction"

    _run(_case())


def test_process_incoming_message_extracts_device_sent_destination() -> None:
    async def _case() -> None:
        msg = wa_pb2.Message()
        msg.deviceSentMessage.destinationJid = "123@s.whatsapp.net"
        msg.deviceSentMessage.message.conversation = "mirror hi"
        node = BinaryNode(
            tag="message",
            attrs={"id": "m3", "from": "555@s.whatsapp.net", "type": "text"},
            content=msg.SerializeToString(),
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.text == "mirror hi"
        assert parsed.destination_jid == "123@s.whatsapp.net"
        assert parsed.message_type == "device_sent"

    _run(_case())


def test_process_incoming_message_extracts_document_content() -> None:
    async def _case() -> None:
        document_payload = (
            _encode_string(1, "https://cdn.example/doc.pdf")
            + _encode_string(2, "application/pdf")
            + _encode_string(8, "doc.pdf")
            + _encode_string(20, "invoice")
        )
        message_payload = _encode_len_delimited(7, document_payload)
        node = BinaryNode(
            tag="message",
            attrs={"id": "m-doc", "from": "999@s.whatsapp.net", "type": "document"},
            content=message_payload,
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.media_url == "https://cdn.example/doc.pdf"
        assert parsed.content_type == "document"
        assert parsed.content["file_name"] == "doc.pdf"
        assert parsed.content["caption"] == "invoice"

    _run(_case())


def test_process_incoming_message_extracts_poll_creation_secret() -> None:
    async def _case() -> None:
        secret = bytes(range(32))
        context_info_payload = _encode_len_delimited(3, secret)
        poll_creation_payload = (
            _encode_len_delimited(1, b"enc-key")
            + _encode_string(2, "Lunch?")
            + _encode_len_delimited(5, context_info_payload)
        )
        message_payload = _encode_len_delimited(49, poll_creation_payload)
        node = BinaryNode(
            tag="message",
            attrs={"id": "m-poll-create", "from": "999@s.whatsapp.net", "type": "poll"},
            content=message_payload,
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.content_type == "poll_creation"
        assert parsed.message_secret_b64 == b64encode(secret).decode("ascii")
        assert parsed.content["name"] == "Lunch?"

    _run(_case())


def test_process_incoming_message_extracts_protocol_revoke() -> None:
    async def _case() -> None:
        protocol_key = _encode_string(3, "target-mid")
        protocol_payload = _encode_len_delimited(1, protocol_key) + _encode_varint_field(2, 0)
        message_payload = _encode_len_delimited(12, protocol_payload)
        node = BinaryNode(
            tag="message",
            attrs={"id": "m4", "from": "999@s.whatsapp.net", "type": "protocol"},
            content=message_payload,
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.protocol_type == "REVOKE"
        assert parsed.target_message_id == "target-mid"
        assert parsed.message_type == "protocol_revoke"

    _run(_case())


def test_process_incoming_message_extracts_protocol_edit() -> None:
    async def _case() -> None:
        edited = wa_pb2.Message()
        edited.conversation = "edited hi"
        protocol_key = _encode_string(3, "target-mid")
        protocol_payload = (
            _encode_len_delimited(1, protocol_key)
            + _encode_varint_field(2, 14)
            + _encode_len_delimited(14, edited.SerializeToString())
            + _encode_varint_field(15, 1000)
        )
        message_payload = _encode_len_delimited(12, protocol_payload)
        node = BinaryNode(
            tag="message",
            attrs={"id": "m5", "from": "999@s.whatsapp.net", "type": "protocol"},
            content=message_payload,
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.protocol_type == "MESSAGE_EDIT"
        assert parsed.edited_text == "edited hi"
        assert parsed.target_message_id == "target-mid"
        assert parsed.message_type == "protocol_edit"

    _run(_case())


def test_process_incoming_message_extracts_app_state_sync_key_ids() -> None:
    async def _case() -> None:
        key_id_payload = _encode_len_delimited(1, b"key-1")
        key_data_payload = _encode_len_delimited(1, b"\x11" * 32)
        key_item_payload = _encode_len_delimited(1, key_id_payload) + _encode_len_delimited(2, key_data_payload)
        share_payload = _encode_len_delimited(1, key_item_payload)
        protocol_payload = _encode_varint_field(2, 6) + _encode_len_delimited(7, share_payload)
        message_payload = _encode_len_delimited(12, protocol_payload)
        node = BinaryNode(
            tag="message",
            attrs={"id": "m6", "from": "999@s.whatsapp.net", "type": "protocol"},
            content=message_payload,
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.protocol_type == "APP_STATE_SYNC_KEY_SHARE"
        assert parsed.app_state_key_ids == [b64encode(b"key-1").decode("ascii")]

    _run(_case())


def test_process_incoming_message_extracts_encrypted_reaction() -> None:
    async def _case() -> None:
        key_payload = _encode_string(3, "target-mid")
        enc_reaction_payload = (
            _encode_len_delimited(1, key_payload)
            + _encode_len_delimited(2, b"enc-react")
            + _encode_len_delimited(3, b"iv-react")
        )
        message_payload = _encode_len_delimited(56, enc_reaction_payload)
        node = BinaryNode(
            tag="message",
            attrs={"id": "m7", "from": "999@s.whatsapp.net", "type": "reaction"},
            content=message_payload,
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.message_type == "reaction_encrypted"
        assert parsed.encrypted_reaction is not None
        assert parsed.encrypted_reaction["target_message_id"] == "target-mid"

    _run(_case())


def test_process_incoming_message_extracts_encrypted_event_response() -> None:
    async def _case() -> None:
        key_payload = _encode_string(3, "event-mid")
        enc_event_payload = (
            _encode_len_delimited(1, key_payload)
            + _encode_len_delimited(2, b"enc-event")
            + _encode_len_delimited(3, b"iv-event")
        )
        message_payload = _encode_len_delimited(76, enc_event_payload)
        node = BinaryNode(
            tag="message",
            attrs={"id": "m8", "from": "999@s.whatsapp.net", "type": "event"},
            content=message_payload,
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.message_type == "event_response_encrypted"
        assert parsed.event_response is not None
        assert parsed.event_response["event_creation_message_id"] == "event-mid"

    _run(_case())


def test_process_incoming_message_extracts_encrypted_poll_update() -> None:
    async def _case() -> None:
        key_payload = _encode_string(3, "poll-mid")
        vote_payload = _encode_len_delimited(1, b"enc-vote") + _encode_len_delimited(2, b"iv-vote")
        poll_update_payload = (
            _encode_len_delimited(1, key_payload)
            + _encode_len_delimited(2, vote_payload)
            + _encode_varint_field(4, 9999)
        )
        message_payload = _encode_len_delimited(50, poll_update_payload)
        node = BinaryNode(
            tag="message",
            attrs={"id": "m9", "from": "999@s.whatsapp.net", "type": "poll"},
            content=message_payload,
        )
        fake_client = _FakeClient()
        parsed = await process_incoming_message(node, fake_client)
        assert parsed.message_type == "poll_update_encrypted"
        assert parsed.poll_update is not None
        assert parsed.poll_update["poll_creation_message_id"] == "poll-mid"
        assert parsed.poll_update["sender_timestamp_ms"] == 9999

    _run(_case())


def test_process_incoming_message_decrypts_poll_update_when_secret_exists() -> None:
    async def _case() -> None:
        poll_message_id = "poll-mid"
        creator_jid = "creator@s.whatsapp.net"
        voter_jid = "999@s.whatsapp.net"
        secret = bytes(range(32))
        iv = bytes(range(12))
        vote_plain = _encode_len_delimited(1, b"opt-a")
        vote_key = _derive_addon_key(
            addon_label="Poll Vote",
            message_id=poll_message_id,
            creator_jid=creator_jid,
            actor_jid=voter_jid,
            message_secret=secret,
        )
        vote_cipher = aes_encrypt(vote_plain, vote_key, iv, f"{poll_message_id}\x00{voter_jid}".encode("utf-8"))

        key_payload = _encode_string(1, creator_jid) + _encode_string(3, poll_message_id)
        vote_payload = _encode_len_delimited(1, vote_cipher) + _encode_len_delimited(2, iv)
        poll_update_payload = _encode_len_delimited(1, key_payload) + _encode_len_delimited(2, vote_payload)
        message_payload = _encode_len_delimited(50, poll_update_payload)

        fake_client = _FakeClient()
        fake_client.creds.additional_data = {"message_secrets": {poll_message_id: b64encode(secret).decode("ascii")}}
        parsed = await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m10", "from": voter_jid, "type": "poll"},
                content=message_payload,
            ),
            fake_client,
        )
        assert parsed.poll_update is not None
        assert parsed.poll_update["decrypted"] is True
        assert parsed.poll_update["decrypted_vote"]["selected_options_b64"] == [b64encode(b"opt-a").decode("ascii")]

    _run(_case())


def test_process_incoming_message_decrypts_event_response_when_secret_exists() -> None:
    async def _case() -> None:
        event_message_id = "event-mid"
        creator_jid = "creator@s.whatsapp.net"
        responder_jid = "999@s.whatsapp.net"
        secret = bytes(range(32, 64))
        iv = bytes(range(16, 28))
        response_plain = _encode_varint_field(1, 1) + _encode_varint_field(2, 123)
        response_key = _derive_addon_key(
            addon_label="Event Response",
            message_id=event_message_id,
            creator_jid=creator_jid,
            actor_jid=responder_jid,
            message_secret=secret,
        )
        response_cipher = aes_encrypt(
            response_plain,
            response_key,
            iv,
            f"{event_message_id}\x00{responder_jid}".encode("utf-8"),
        )

        key_payload = _encode_string(1, creator_jid) + _encode_string(3, event_message_id)
        event_payload = (
            _encode_len_delimited(1, key_payload)
            + _encode_len_delimited(2, response_cipher)
            + _encode_len_delimited(3, iv)
        )
        message_payload = _encode_len_delimited(76, event_payload)

        fake_client = _FakeClient()
        fake_client.creds.additional_data = {"message_secrets": {event_message_id: b64encode(secret).decode("ascii")}}
        parsed = await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m11", "from": responder_jid, "type": "event"},
                content=message_payload,
            ),
            fake_client,
        )
        assert parsed.event_response is not None
        assert parsed.event_response["decrypted"] is True
        assert parsed.event_response["decrypted_response"]["response_type"] == 1
        assert parsed.event_response["decrypted_response"]["timestamp_ms"] == 123

    _run(_case())


def test_process_incoming_message_old_counter_decrypt_logs_debug(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _case() -> None:
        async def _raise_old_counter(*args: object, **kwargs: object) -> bytes:
            del args, kwargs
            raise ValueError("signal decryption failed: message with old counter 4 / 0")

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _raise_old_counter)
        caplog.set_level(logging.DEBUG, logger="waton.utils.process_message")

        fake_client = _FakeClient()
        await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m-old-counter", "from": "999@s.whatsapp.net", "type": "text"},
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            ),
            fake_client,
        )

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        debugs = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert warnings == []
        assert any("old counter" in r.getMessage().lower() for r in debugs)

    _run(_case())


def test_process_incoming_message_other_decrypt_error_logs_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _case() -> None:
        async def _raise_other(*args: object, **kwargs: object) -> bytes:
            del args, kwargs
            raise ValueError("signal decryption failed: invalid mac")

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _raise_other)
        caplog.set_level(logging.DEBUG, logger="waton.utils.process_message")

        fake_client = _FakeClient()
        await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m-invalid-mac", "from": "999@s.whatsapp.net", "type": "text"},
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            ),
            fake_client,
        )

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert any("invalid mac" in r.getMessage().lower() for r in warnings)

    _run(_case())


def test_process_incoming_message_uses_lid_mapping_for_pn_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        plaintext = wa_pb2.Message()
        plaintext.conversation = "hello from mapped lid"
        padded = _write_random_pad_max16(plaintext.SerializeToString())

        async def _mapped_lid(self: object, pn_jid: str) -> str | None:
            del self
            assert pn_jid == "999@s.whatsapp.net"
            return "111@lid"

        async def _decrypt(self: object, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del self, ciphertext
            assert jid == "111@lid"
            assert type_str == "msg"
            return padded

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.get_lid_for_pn", _mapped_lid)
        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _decrypt)

        fake_client = _FakeClient()
        parsed = await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m-lid-map", "from": "999@s.whatsapp.net", "type": "text"},
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            ),
            fake_client,
        )
        assert parsed.text == "hello from mapped lid"

    _run(_case())


def test_process_incoming_message_decrypts_enc_when_v_attr_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        plaintext = wa_pb2.Message()
        plaintext.conversation = "works without enc.v"
        padded = _write_random_pad_max16(plaintext.SerializeToString())

        async def _decrypt(self: object, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del self, ciphertext
            assert jid == "999@s.whatsapp.net"
            assert type_str == "msg"
            return padded

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _decrypt)

        fake_client = _FakeClient()
        parsed = await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m-no-v", "from": "999@s.whatsapp.net", "type": "text"},
                content=[BinaryNode(tag="enc", attrs={"type": "msg"}, content=b"cipher")],
            ),
            fake_client,
        )
        assert parsed.text == "works without enc.v"

    _run(_case())


def test_process_incoming_message_falls_back_to_pn_after_lid_decrypt_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _case() -> None:
        plaintext = wa_pb2.Message()
        plaintext.conversation = "fallback works"
        padded = _write_random_pad_max16(plaintext.SerializeToString())
        attempts: list[str] = []

        async def _mapped_lid(self: object, pn_jid: str) -> str | None:
            del self
            assert pn_jid == "999@s.whatsapp.net"
            return "111@lid"

        async def _decrypt(self: object, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del self, type_str, ciphertext
            attempts.append(jid)
            if jid == "111@lid":
                raise ValueError("No active session for 111@lid, cannot decrypt 'msg'")
            return padded

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.get_lid_for_pn", _mapped_lid)
        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _decrypt)

        fake_client = _FakeClient()
        parsed = await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={"id": "m-lid-fallback", "from": "999@s.whatsapp.net", "type": "text"},
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            ),
            fake_client,
        )
        assert attempts == ["111@lid", "999@s.whatsapp.net"]
        assert parsed.text == "fallback works"

    _run(_case())


def test_process_incoming_message_falls_back_to_recipient_pn_when_addressing_mode_is_pn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _case() -> None:
        plaintext = wa_pb2.Message()
        plaintext.conversation = "fallback via recipient pn"
        padded = _write_random_pad_max16(plaintext.SerializeToString())
        attempts: list[str] = []

        async def _decrypt(self: object, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del self, type_str, ciphertext
            attempts.append(jid)
            if jid == "179981124669483:0@lid":
                raise ValueError("No active session for 179981124669483:0@lid, cannot decrypt 'msg'")
            return padded

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _decrypt)

        fake_client = _FakeClient()
        parsed = await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={
                    "id": "m-map-recipient-fallback",
                    "from": "179981124669483:0@lid",
                    "addressing_mode": "pn",
                    "recipient_pn": "628980145555@s.whatsapp.net",
                    "type": "text",
                },
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            ),
            fake_client,
        )

        assert attempts == ["179981124669483:0@lid", "628980145555:0@s.whatsapp.net"]
        assert parsed.text == "fallback via recipient pn"

    _run(_case())


def test_process_incoming_message_stores_mapping_from_recipient_pn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _case() -> None:
        plaintext = wa_pb2.Message()
        plaintext.conversation = "store mapping from recipient pn"
        padded = _write_random_pad_max16(plaintext.SerializeToString())

        async def _decrypt(self: object, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del self, jid, type_str, ciphertext
            return padded

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _decrypt)

        fake_client = _FakeClient()
        await process_incoming_message(
            BinaryNode(
                tag="message",
                attrs={
                    "id": "m-map-recipient",
                    "from": "179981124669483:0@lid",
                    "recipient_pn": "628980145555@s.whatsapp.net",
                    "type": "text",
                },
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            ),
            fake_client,
        )

        lid_mapping = (fake_client.creds.additional_data or {}).get("lid_mapping", {})
        assert lid_mapping.get("lid_to_pn_user", {}).get("179981124669483") == "628980145555"
        assert lid_mapping.get("pn_to_lid_user", {}).get("628980145555") == "179981124669483"

    _run(_case())


def test_derive_media_keys_lengths() -> None:
    keys = derive_media_keys(bytes(range(32)), "image")
    assert len(keys["iv"]) == 16
    assert len(keys["cipher_key"]) == 32
    assert len(keys["mac_key"]) == 32
    assert len(keys["ref_key"]) == 32
