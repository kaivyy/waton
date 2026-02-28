import asyncio

import pytest

from waton.protocol.group_cipher import GroupCipher
from waton.protocol.signal_repo import SignalRepository
from waton.utils.auth import init_auth_creds


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


def _run(coro):
    return asyncio.run(coro)


def test_signal_repository_generate_prekeys() -> None:
    async def _case() -> None:
        storage = _MemoryStorage()
        creds = init_auth_creds()
        repo = SignalRepository(creds, storage)
        keys = await repo.generate_prekeys(3)
        assert len(keys) == 3
        assert keys[0]["keyId"] == 1
        assert keys[2]["keyId"] == 3
        assert creds.next_pre_key_id == 4
        assert await storage.get_prekey(2) is not None

    _run(_case())


def test_signal_encrypt_uses_wrapper_and_updates_session(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_encrypt(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        plaintext: bytes,
    ) -> tuple[str, bytes, bytes]:
        assert session == b"s0"
        assert isinstance(identity_private, bytes)
        assert registration_id > 0
        assert remote_name == "user"
        assert remote_device == 0
        assert plaintext == b"hello"
        return "pkmsg", b"cipher", b"s1"

    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_encrypt", _fake_encrypt)

    async def _case() -> None:
        storage = _MemoryStorage()
        creds = init_auth_creds()
        repo = SignalRepository(creds, storage)
        await storage.save_session("user.0", b"s0")
        msg_type, ciphertext = await repo.encrypt_message("user@s.whatsapp.net", b"hello")
        assert msg_type == "pkmsg"
        assert ciphertext == b"cipher"
        assert await storage.get_session("user.0") == b"s1"

    _run(_case())


def test_signal_decrypt_pkmsg(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_decrypt_prekey(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        prekey_id: int | None,
        prekey_private: bytes | None,
        signed_prekey_id: int,
        signed_prekey_private: bytes,
        ciphertext: bytes,
    ):
        assert prekey_id == 123
        assert signed_prekey_id == 456
        assert ciphertext == b"\x33\x08\x7b\x10\xc8\x03"
        return {"type": "msg", "ciphertext": b"decrypted_payload", "session": b"s1"}

    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_decrypt_prekey", _fake_decrypt_prekey)

    async def _case() -> None:
        storage = _MemoryStorage()
        creds = init_auth_creds()
        # Mock the prekey response
        await storage.save_prekey(123, b"prekey_private")
        
        # Build fake protobuf payload manually: version byte + preKeyId (tag 1) + signedPreKeyId (tag 2)
        # tag 1, type 0 = 0x08. value = 123 (0x7b)
        # tag 2, type 0 = 0x10. value = 456 (0xc8 0x03)
        payload = b"\x33\x08\x7b\x10\xc8\x03"
        
        repo = SignalRepository(creds, storage)
        out = await repo.decrypt_message("user@s.whatsapp.net", "pkmsg", payload)
        assert out == b"decrypted_payload"
        assert await storage.get_session("user.0") == b"s1"

    _run(_case())

def test_signal_decrypt_msg(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_decrypt_whisper(
        session: bytes,
        identity_private: bytes,
        registration_id: int,
        remote_name: str,
        remote_device: int,
        ciphertext: bytes,
    ):
        assert session == b"s0"
        return {"type": "msg", "ciphertext": b"whisper_payload", "session": b"s1"}

    monkeypatch.setattr("waton.protocol.signal_repo.signal_session_decrypt_whisper", _fake_decrypt_whisper)

    async def _case() -> None:
        storage = _MemoryStorage()
        creds = init_auth_creds()
        repo = SignalRepository(creds, storage)
        await storage.save_session("user.0", b"s0")
        
        out = await repo.decrypt_message("user@s.whatsapp.net", "msg", b"cipher")
        assert out == b"whisper_payload"
        assert await storage.get_session("user.0") == b"s1"

    _run(_case())


def test_inject_session_from_prekey_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
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
        assert session is None
        assert isinstance(identity_private, bytes)
        assert registration_id > 0
        assert remote_name == "user"
        assert remote_device == 0
        assert remote_registration_id == 7
        assert remote_identity_key == b"i" * 32
        assert signed_prekey_id == 11
        assert signed_prekey_public == b"s" * 32
        assert signed_prekey_signature == b"g" * 64
        assert prekey_id == 13
        assert prekey_public == b"p" * 32
        return b"session-new"

    monkeypatch.setattr("waton.protocol.signal_repo.signal_process_prekey_bundle", _fake_process)

    async def _case() -> None:
        storage = _MemoryStorage()
        creds = init_auth_creds()
        repo = SignalRepository(creds, storage)
        await repo.inject_session_from_prekey_bundle(
            "user@s.whatsapp.net",
            registration_id=7,
            identity_key=b"i" * 32,
            signed_prekey_id=11,
            signed_prekey_public=b"s" * 32,
            signed_prekey_signature=b"g" * 64,
            prekey_id=13,
            prekey_public=b"p" * 32,
        )
        assert await storage.get_session("user.0") == b"session-new"

    _run(_case())


def test_group_cipher_contracts() -> None:
    async def _case() -> None:
        storage = _MemoryStorage()
        cipher = GroupCipher("group@g.us", storage)
        out = await cipher.encrypt("me@s.whatsapp.net", b"hello")
        assert out == b"hello"
        # save key for author, then decrypt
        await storage.save_sender_key("group@g.us", "alice@s.whatsapp.net", b"k")
        pt = await cipher.decrypt("alice@s.whatsapp.net", b"cipher")
        assert pt == b"cipher"

    _run(_case())


def test_signal_repository_store_and_lookup_lid_mapping() -> None:
    async def _case() -> None:
        storage = _MemoryStorage()
        creds = init_auth_creds()
        repo = SignalRepository(creds, storage)

        await repo.store_lid_pn_mapping("179981124669483@lid", "628980145555@s.whatsapp.net")

        assert await repo.get_lid_for_pn("628980145555@s.whatsapp.net") == "179981124669483@lid"
        assert await repo.get_pn_for_lid("179981124669483@lid") == "628980145555@s.whatsapp.net"

    _run(_case())


def test_signal_repository_store_lid_mapping_detects_reverse_side_change() -> None:
    async def _case() -> None:
        storage = _MemoryStorage()
        creds = init_auth_creds()
        creds.additional_data = {
            "lid_mapping": {
                "pn_to_lid_user": {"628980145555": "179981124669483"},
                "lid_to_pn_user": {},
            }
        }
        repo = SignalRepository(creds, storage)

        changed = await repo.store_lid_pn_mapping("179981124669483@lid", "628980145555@s.whatsapp.net")

        assert changed is True
        assert await repo.get_pn_for_lid("179981124669483@lid") == "628980145555@s.whatsapp.net"

    _run(_case())


def test_signal_repository_migrate_session_copies_bytes() -> None:
    async def _case() -> None:
        storage = _MemoryStorage()
        creds = init_auth_creds()
        repo = SignalRepository(creds, storage)
        await repo.save_session("628980145555@s.whatsapp.net", b"session-pn")

        migrated = await repo.migrate_session("628980145555@s.whatsapp.net", "179981124669483@lid")

        assert migrated is True
        assert await repo.get_session("179981124669483@lid") == b"session-pn"

    _run(_case())
