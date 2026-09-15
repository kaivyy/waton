import pytest

from waton.protocol.group_cipher import GroupCipher


class FakeStorage:
    def __init__(self) -> None:
        self.keys: dict[tuple[str, str], bytes] = {}

    async def get_sender_key(self, group_jid: str, sender_jid: str) -> bytes | None:
        return self.keys.get((group_jid, sender_jid))

    async def save_sender_key(self, group_jid: str, sender_jid: str, key: bytes) -> None:
        self.keys[(group_jid, sender_jid)] = key


@pytest.mark.asyncio
async def test_group_cipher_roundtrip_no_stub_values() -> None:
    storage = FakeStorage()
    gc = GroupCipher("123@g.us", storage)
    ct = await gc.encrypt("111@s.whatsapp.net", b"hello")
    pt = await gc.decrypt("111@s.whatsapp.net", ct)
    assert pt == b"hello"
    assert b"stub" not in ct


@pytest.mark.asyncio
async def test_process_sender_key_distribution_sets_key_for_participant() -> None:
    storage = FakeStorage()
    gc = GroupCipher("123@g.us", storage)

    await gc.process_sender_key_distribution("222@s.whatsapp.net", b"distribution-payload")
    key = await gc.export_sender_key("222@s.whatsapp.net")

    assert key is not None
    assert len(key) == 32


@pytest.mark.asyncio
async def test_process_sender_key_distribution_rejects_empty_payload() -> None:
    storage = FakeStorage()
    gc = GroupCipher("123@g.us", storage)

    with pytest.raises(ValueError, match="cannot be empty"):
        await gc.process_sender_key_distribution("333@s.whatsapp.net", b"")


@pytest.mark.asyncio
async def test_export_import_sender_key_distribution_roundtrip() -> None:
    storage = FakeStorage()
    gc1 = GroupCipher("123@g.us", storage)
    gc2 = GroupCipher("123@g.us", storage)

    await gc1.import_sender_key("444@s.whatsapp.net", b"seed-key")
    distribution = await gc1.export_sender_key_distribution("444@s.whatsapp.net")

    assert distribution is not None
    assert distribution.startswith(b"v1:")

    await gc2.process_sender_key_distribution("555@s.whatsapp.net", distribution)
    key_444 = await gc1.export_sender_key("444@s.whatsapp.net")
    key_555 = await gc2.export_sender_key("555@s.whatsapp.net")
    assert key_444 == key_555


@pytest.mark.asyncio
async def test_has_sender_key_reflects_storage_state() -> None:
    storage = FakeStorage()
    gc = GroupCipher("123@g.us", storage)

    assert await gc.has_sender_key("666@s.whatsapp.net") is False
    await gc.import_sender_key("666@s.whatsapp.net", b"seed-key")
    assert await gc.has_sender_key("666@s.whatsapp.net") is True


@pytest.mark.asyncio
async def test_signal_repository_group_message_roundtrip() -> None:
    from waton.protocol.signal_repo import SignalRepository
    from waton.utils.auth import init_auth_creds

    storage = FakeStorage()
    creds = init_auth_creds()
    repo = SignalRepository(creds, storage)

    group_jid = "120363000000000000@g.us"
    author_jid = "628123456789@s.whatsapp.net"

    # Encrypt group message
    ciphertext, skdm = await repo.encrypt_group_message(group_jid, author_jid, b"hello group")
    assert len(ciphertext) > 0
    assert len(skdm) > 0

    # Decrypt group message with skmsg
    plaintext = await repo.decrypt_group_message(group_jid, author_jid, ciphertext)
    assert plaintext == b"hello group"


@pytest.mark.asyncio
async def test_decode_incoming_group_message_skmsg() -> None:
    from waton.client.messages import _write_random_pad_max16
    from waton.client.messages_recv import decode_incoming_message_node
    from waton.protocol.binary_node import BinaryNode
    from waton.protocol.protobuf import wa_pb2
    from waton.protocol.signal_repo import SignalRepository
    from waton.utils.auth import init_auth_creds

    storage = FakeStorage()
    creds = init_auth_creds()
    repo = SignalRepository(creds, storage)

    group_jid = "120363000000000000@g.us"
    author_jid = "628123456789@s.whatsapp.net"

    msg = wa_pb2.Message()
    msg.conversation = "Hello from group member!"
    payload = msg.SerializeToString()
    padded = _write_random_pad_max16(payload)

    ciphertext, _ = await repo.encrypt_group_message(group_jid, author_jid, padded)

    node = BinaryNode(
        tag="message",
        attrs={"id": "grp1", "from": group_jid, "participant": author_jid, "type": "text"},
        content=[
            BinaryNode(tag="enc", attrs={"v": "2", "type": "skmsg"}, content=ciphertext)
        ],
    )

    decoded = await decode_incoming_message_node(node, repo)
    assert decoded["type"] == "messages.upsert"
    msg = decoded["message"]
    assert msg["text"] == "Hello from group member!"
    assert msg["from"] == group_jid
    assert msg["participant"] == author_jid



@pytest.mark.asyncio
async def test_messages_api_send_group_payload_uses_skmsg() -> None:
    from waton.client.messages import MessagesAPI
    from waton.protocol.binary_node import BinaryNode
    from waton.utils.auth import init_auth_creds

    class FakeClient:
        def __init__(self) -> None:
            self.creds = init_auth_creds()
            self.creds.me = {"id": "628111111111:0@s.whatsapp.net"}
            self.storage = FakeStorage()
            self.sent_nodes: list[BinaryNode] = []

        async def send_node(self, node: BinaryNode) -> None:
            self.sent_nodes.append(node)

    client = FakeClient()
    api = MessagesAPI(client)  # type: ignore[arg-type]
    msg_id = await api.send_text("120363000000000000@g.us", "Hi everyone in group!")

    assert msg_id is not None
    assert len(client.sent_nodes) == 1
    sent_node = client.sent_nodes[0]
    assert sent_node.tag == "message"
    assert sent_node.attrs["to"] == "120363000000000000@g.us"
    enc_child = sent_node.content[0]
    assert enc_child.tag == "enc"
    assert enc_child.attrs["type"] == "skmsg"
    assert enc_child.attrs["v"] == "2"
    assert len(enc_child.content) > 0


