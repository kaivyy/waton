import asyncio
from pathlib import Path

from waton.infra.storage_json import JsonStorage
from waton.infra.storage_sqlite import SQLiteStorage
from waton.utils.auth import init_auth_creds


def _run(coro):
    return asyncio.run(coro)


def _assert_creds_roundtrip(original, loaded) -> None:
    assert loaded is not None
    assert loaded.registration_id == original.registration_id
    assert loaded.noise_key["private"] == original.noise_key["private"]
    assert loaded.noise_key["public"] == original.noise_key["public"]
    assert loaded.pairing_ephemeral_key_pair["private"] == original.pairing_ephemeral_key_pair["private"]
    assert loaded.pairing_ephemeral_key_pair["public"] == original.pairing_ephemeral_key_pair["public"]
    assert loaded.signed_identity_key["private"] == original.signed_identity_key["private"]
    assert loaded.signed_identity_key["public"] == original.signed_identity_key["public"]
    assert loaded.signed_pre_key["keyId"] == original.signed_pre_key["keyId"]
    assert loaded.signed_pre_key["signature"] == original.signed_pre_key["signature"]
    assert loaded.adv_secret_key == original.adv_secret_key


def test_sqlite_storage_roundtrip() -> None:
    async def _case() -> None:
        storage = SQLiteStorage(":memory:")
        creds = init_auth_creds()

        await storage.save_creds(creds)
        loaded = await storage.get_creds()
        _assert_creds_roundtrip(creds, loaded)

        await storage.save_session("user@s.whatsapp.net", b"session-bytes")
        assert await storage.get_session("user@s.whatsapp.net") == b"session-bytes"

        await storage.save_prekey(7, b"prekey-bytes")
        assert await storage.get_prekey(7) == b"prekey-bytes"

        await storage.save_sender_key("group@g.us", "user@s.whatsapp.net", b"sender-key")
        assert await storage.get_sender_key("group@g.us", "user@s.whatsapp.net") == b"sender-key"
        await storage.close()

    _run(_case())


def test_json_storage_roundtrip() -> None:
    async def _case() -> None:
        base = Path(".tmp-tests-json-storage")
        base.mkdir(parents=True, exist_ok=True)
        storage = JsonStorage(base / "state.json")
        creds = init_auth_creds()

        await storage.save_creds(creds)
        loaded = await storage.get_creds()
        _assert_creds_roundtrip(creds, loaded)

        await storage.save_session("user@s.whatsapp.net", b"session")
        assert await storage.get_session("user@s.whatsapp.net") == b"session"

        await storage.save_prekey(11, b"prekey")
        assert await storage.get_prekey(11) == b"prekey"

        await storage.save_sender_key("group@g.us", "user@s.whatsapp.net", b"sender")
        assert await storage.get_sender_key("group@g.us", "user@s.whatsapp.net") == b"sender"

    _run(_case())
