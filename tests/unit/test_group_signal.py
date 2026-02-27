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
