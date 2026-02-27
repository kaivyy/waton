import pytest
from waton.protocol.group_cipher import GroupCipher

class FakeStorage:
    def __init__(self):
        self.keys = {}
    async def get_sender_key(self, group_jid, sender_jid):
        return self.keys.get((group_jid, sender_jid))
    async def save_sender_key(self, group_jid, sender_jid, key):
        self.keys[(group_jid, sender_jid)] = key

@pytest.mark.asyncio
async def test_group_cipher_roundtrip_no_stub_values() -> None:
    storage = FakeStorage()
    gc = GroupCipher("123@g.us", storage)
    ct = await gc.encrypt("111@s.whatsapp.net", b"hello")
    pt = await gc.decrypt("111@s.whatsapp.net", ct)
    assert pt == b"hello"
    assert b"stub" not in ct
