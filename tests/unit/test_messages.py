import asyncio
from base64 import b64encode
from typing import Any

import pytest

from pywa.client.messages import MessagesAPI
from pywa.protocol.binary_node import BinaryNode
from pywa.protocol.protobuf import wa_pb2
from pywa.utils.media_utils import derive_media_keys
from pywa.utils.process_message import process_incoming_message
from pywa.utils.auth import init_auth_creds


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

    monkeypatch.setattr("pywa.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)
    monkeypatch.setattr("pywa.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)

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


def test_process_incoming_message_extracts_text() -> None:
    msg = wa_pb2.Message()
    msg.conversation = "incoming hello"
    node = BinaryNode(
        tag="message",
        attrs={"id": "m1", "from": "999@s.whatsapp.net", "type": "text"},
        content=msg.SerializeToString(),
    )
    parsed = process_incoming_message(node)
    assert parsed.id == "m1"
    assert parsed.text == "incoming hello"
    assert parsed.from_jid == "999@s.whatsapp.net"


def test_derive_media_keys_lengths() -> None:
    keys = derive_media_keys(bytes(range(32)), "image")
    assert len(keys["iv"]) == 16
    assert len(keys["cipher_key"]) == 32
    assert len(keys["mac_key"]) == 32
    assert len(keys["ref_key"]) == 32
