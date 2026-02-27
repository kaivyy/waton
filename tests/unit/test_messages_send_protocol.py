from __future__ import annotations

import asyncio
from base64 import b64encode
from typing import Any

import pytest

from waton.client.messages import MessagesAPI, _unpad_random_max16
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import wa_pb2
from waton.protocol.protobuf.wire import _iter_fields
from waton.utils.auth import init_auth_creds
from waton.utils.protocol_message import decrypt_event_response, decrypt_poll_vote


class _MemoryStorage:
    def __init__(self) -> None:
        self.creds = None
        self.sessions: dict[str, bytes] = {}
        self.prekeys: dict[int, bytes] = {}
        self.sender_keys: dict[tuple[str, str], bytes] = {}

    async def get_creds(self) -> Any:
        return self.creds

    async def save_creds(self, creds: Any) -> None:
        self.creds = creds

    async def get_session(self, jid: str) -> bytes | None:
        return self.sessions.get(jid)

    async def save_session(self, jid: str, data: bytes) -> None:
        self.sessions[jid] = data

    async def get_prekey(self, key_id: int) -> bytes | None:
        return self.prekeys.get(key_id)

    async def save_prekey(self, key_id: int, data: bytes) -> None:
        self.prekeys[key_id] = data

    async def get_sender_key(self, group_jid: str, sender_jid: str) -> bytes | None:
        return self.sender_keys.get((group_jid, sender_jid))

    async def save_sender_key(self, group_jid: str, sender_jid: str, data: bytes) -> None:
        self.sender_keys[(group_jid, sender_jid)] = data


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
        del timeout
        xmlns = node.attrs.get("xmlns", "")
        if xmlns == "usync":
            return self._handle_usync_query(node)
        return self._handle_encrypt_query(node)

    def _handle_usync_query(self, node: BinaryNode) -> BinaryNode:
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
                    content=[BinaryNode(tag="list", attrs={}, content=user_results)],
                )
            ],
        )

    def _handle_encrypt_query(self, node: BinaryNode) -> BinaryNode:
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


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _capture_plaintexts(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
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
        del (
            session,
            identity_private,
            remote_registration_id,
            remote_identity_key,
            signed_prekey_id,
            signed_prekey_public,
            signed_prekey_signature,
            prekey_id,
            prekey_public,
        )
        assert registration_id > 0
        return b"session-for-" + remote_name.encode("utf-8") + b"-" + str(remote_device).encode("utf-8")

    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        del identity_private, registration_id
        assert session.startswith(b"session-for-")
        captured_plaintexts.append(plaintext)
        return "msg", b"cipher-" + remote_name.encode("utf-8"), session

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)
    return captured_plaintexts


def _field_bytes(payload: bytes, field: int) -> bytes | None:
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == field and wire_type == 2:
            return bytes(value)
    return None


def _field_varint(payload: bytes, field: int) -> int | None:
    for field_no, wire_type, value in _iter_fields(payload):
        if field_no == field and wire_type == 0:
            return int(value)
    return None


def test_send_delete_builds_protocol_revoke(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_plaintexts(monkeypatch)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        msg_id = await api.send_delete("123@s.whatsapp.net", "target-mid")
        assert msg_id
        assert len(client.sent) == 1
        assert client.sent[0].attrs["type"] == "protocol"

        decoded = [_unpad_random_max16(payload) for payload in captured]
        protocol_payloads = [p for p in decoded if _field_bytes(p, 12) is not None]
        assert protocol_payloads

        protocol = _field_bytes(protocol_payloads[0], 12)
        assert protocol is not None
        assert _field_varint(protocol, 2) == 0
        key = _field_bytes(protocol, 1)
        assert key is not None
        assert _field_bytes(key, 3) == b"target-mid"

    _run(_case())


def test_send_edit_builds_protocol_edit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_plaintexts(monkeypatch)

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        msg_id = await api.send_edit("123@s.whatsapp.net", "target-mid", "edited text", edited_at_ms=1111)
        assert msg_id
        assert len(client.sent) == 1
        assert client.sent[0].attrs["type"] == "protocol"

        decoded = [_unpad_random_max16(payload) for payload in captured]
        protocol_payloads = [p for p in decoded if _field_bytes(p, 12) is not None]
        assert protocol_payloads

        protocol = _field_bytes(protocol_payloads[0], 12)
        assert protocol is not None
        assert _field_varint(protocol, 2) == 14
        assert _field_varint(protocol, 15) == 1111

        edited_payload = _field_bytes(protocol, 14)
        assert edited_payload is not None
        edited = wa_pb2.Message()
        edited.ParseFromString(edited_payload)
        assert edited.conversation == "edited text"

    _run(_case())


def test_send_poll_vote_encrypts_vote_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_plaintexts(monkeypatch)
    secret = bytes(range(32))

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        msg_id = await api.send_poll_vote(
            "123@s.whatsapp.net",
            poll_creation_message_id="poll-mid",
            poll_creator_jid="creator@s.whatsapp.net",
            selected_options=[b"opt-a", b"opt-b"],
            message_secret=secret,
            sender_timestamp_ms=1234,
        )
        assert msg_id
        assert len(client.sent) == 1
        assert client.sent[0].attrs["type"] == "poll_update"

        decoded = [_unpad_random_max16(payload) for payload in captured]
        poll_payloads = [p for p in decoded if _field_bytes(p, 50) is not None]
        assert poll_payloads

        poll_update = _field_bytes(poll_payloads[0], 50)
        assert poll_update is not None
        vote = _field_bytes(poll_update, 2)
        assert vote is not None
        enc_payload = _field_bytes(vote, 1)
        enc_iv = _field_bytes(vote, 2)
        assert enc_payload is not None
        assert enc_iv is not None
        key = _field_bytes(poll_update, 1)
        assert key is not None
        assert _field_bytes(key, 3) == b"poll-mid"

        decrypted = decrypt_poll_vote(
            enc_payload_b64=b64encode(enc_payload).decode("ascii"),
            enc_iv_b64=b64encode(enc_iv).decode("ascii"),
            poll_message_id="poll-mid",
            poll_creator_jid="creator@s.whatsapp.net",
            voter_jid="555@s.whatsapp.net",
            poll_enc_key=secret,
        )
        assert decrypted["selected_options_b64"] == [
            b64encode(b"opt-a").decode("ascii"),
            b64encode(b"opt-b").decode("ascii"),
        ]

    _run(_case())


def test_send_event_response_encrypts_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_plaintexts(monkeypatch)
    secret = bytes(range(32, 64))

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        msg_id = await api.send_event_response(
            "123@s.whatsapp.net",
            event_creation_message_id="event-mid",
            event_creator_jid="creator@s.whatsapp.net",
            response_type=2,
            message_secret=secret,
            timestamp_ms=9876,
            extra_guest_count=1,
        )
        assert msg_id
        assert len(client.sent) == 1
        assert client.sent[0].attrs["type"] == "event_response"

        decoded = [_unpad_random_max16(payload) for payload in captured]
        event_payloads = [p for p in decoded if _field_bytes(p, 76) is not None]
        assert event_payloads

        event_update = _field_bytes(event_payloads[0], 76)
        assert event_update is not None
        enc_payload = _field_bytes(event_update, 2)
        enc_iv = _field_bytes(event_update, 3)
        assert enc_payload is not None
        assert enc_iv is not None
        key = _field_bytes(event_update, 1)
        assert key is not None
        assert _field_bytes(key, 3) == b"event-mid"

        decrypted = decrypt_event_response(
            enc_payload_b64=b64encode(enc_payload).decode("ascii"),
            enc_iv_b64=b64encode(enc_iv).decode("ascii"),
            event_message_id="event-mid",
            event_creator_jid="creator@s.whatsapp.net",
            responder_jid="555@s.whatsapp.net",
            event_enc_key=secret,
        )
        assert decrypted["response_type"] == 2
        assert decrypted["timestamp_ms"] == 9876
        assert decrypted["extra_guest_count"] == 1

    _run(_case())


def test_send_receipts_batch_and_read_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    del monkeypatch

    async def _case() -> None:
        client = _FakeClient()
        api = MessagesAPI(client)
        await api.send_receipts_batch(
            [
                {"remote_jid": "123@s.whatsapp.net", "id": "m1", "participant": None},
                {"remote_jid": "123@s.whatsapp.net", "id": "m2", "participant": None},
                {"remote_jid": "999@g.us", "id": "g1", "participant": "111@s.whatsapp.net"},
            ],
            receipt_type="read",
        )
        assert len(client.sent) == 2
        private_receipt = client.sent[0]
        group_receipt = client.sent[1]
        assert private_receipt.tag == "receipt"
        assert private_receipt.attrs["to"] == "123@s.whatsapp.net"
        assert [item.attrs["id"] for item in private_receipt.content] == ["m1", "m2"]
        assert group_receipt.attrs["participant"] == "111@s.whatsapp.net"

        client.sent.clear()
        await api.read_messages(
            [
                {"remote_jid": "123@s.whatsapp.net", "id": "m3", "participant": None},
                {"remote_jid": "123@s.whatsapp.net", "id": "m4", "participant": None},
            ],
            read_self=True,
        )
        assert len(client.sent) == 1
        assert client.sent[0].attrs["type"] == "read-self"

    _run(_case())
