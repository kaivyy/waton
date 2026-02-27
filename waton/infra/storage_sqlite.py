import asyncio
import aiosqlite
import json
from base64 import b64encode, b64decode
from typing import Any
from waton.utils.auth import AuthCreds, StoragePort
from waton.utils.crypto import generate_keypair

class SQLiteStorage(StoragePort):
    """
    Async SQLite implementation of the StoragePort for persisting 
    auth credentials, signal sessions, and pre-keys.
    """
    def __init__(self, db_path: str = "waton.db"):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def connect(self):
        if not self._db:
            self._db = await aiosqlite.connect(self.db_path)
            await self._init_db()

    async def close(self):
        if self._db:
            await self._db.close()
            self._db = None

    async def _init_db(self):
        await self._db.execute('''
            CREATE TABLE IF NOT EXISTS creds (
                id TEXT PRIMARY KEY,
                data TEXT
            )
        ''')
        await self._db.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                jid TEXT PRIMARY KEY,
                data TEXT
            )
        ''')
        await self._db.execute('''
            CREATE TABLE IF NOT EXISTS prekeys (
                key_id INTEGER PRIMARY KEY,
                data TEXT
            )
        ''')
        await self._db.execute('''
            CREATE TABLE IF NOT EXISTS sender_keys (
                group_jid TEXT,
                sender_jid TEXT,
                data TEXT,
                PRIMARY KEY (group_jid, sender_jid)
            )
        ''')
        await self._db.commit()

    def _b64_encode(self, data: bytes) -> str:
        return b64encode(data).decode('utf-8')

    def _b64_decode(self, data: str) -> bytes:
        return b64decode(data)
        
    def _creds_to_json(self, creds: AuthCreds) -> str:
        d = {
            "noise_key": {
                "private": self._b64_encode(creds.noise_key["private"]),
                "public": self._b64_encode(creds.noise_key["public"])
            },
            "pairing_ephemeral_key_pair": {
                "private": self._b64_encode(creds.pairing_ephemeral_key_pair["private"]),
                "public": self._b64_encode(creds.pairing_ephemeral_key_pair["public"]),
            },
            "signed_identity_key": {
                "private": self._b64_encode(creds.signed_identity_key["private"]),
                "public": self._b64_encode(creds.signed_identity_key["public"])
            },
            "signed_pre_key": {
                "keyPair": {
                    "private": self._b64_encode(creds.signed_pre_key["keyPair"]["private"]),
                    "public": self._b64_encode(creds.signed_pre_key["keyPair"]["public"])
                },
                "signature": self._b64_encode(creds.signed_pre_key["signature"]),
                "keyId": creds.signed_pre_key["keyId"]
            },
            "registration_id": creds.registration_id,
            "adv_secret_key": creds.adv_secret_key,
            "next_pre_key_id": creds.next_pre_key_id,
            "first_unuploaded_pre_key_id": creds.first_unuploaded_pre_key_id,
            "processed_history_messages": creds.processed_history_messages,
            "account_sync_counter": creds.account_sync_counter,
            "account_settings": creds.account_settings,
            "registered": creds.registered,
            "pairing_code": creds.pairing_code,
            "last_prop_hash": creds.last_prop_hash,
            "routing_info": self._b64_encode(creds.routing_info) if creds.routing_info else None,
            "additional_data": creds.additional_data,
            "account": creds.account,
            "me": creds.me,
            "server_hashes": creds.server_hashes,
            "signal_identities": creds.signal_identities,
            "platform": creds.platform,
        }
        return json.dumps(d)

    def _json_to_creds(self, j: str) -> AuthCreds:
        d = json.loads(j)
        noise_key = {
            "private": self._b64_decode(d["noise_key"]["private"]),
            "public": self._b64_decode(d["noise_key"]["public"])
        }
        pairing_ephemeral = d.get("pairing_ephemeral_key_pair")
        if pairing_ephemeral:
            pairing_key = {
                "private": self._b64_decode(pairing_ephemeral["private"]),
                "public": self._b64_decode(pairing_ephemeral["public"]),
            }
        else:
            pairing_key = generate_keypair()
        id_key = {
            "private": self._b64_decode(d["signed_identity_key"]["private"]),
            "public": self._b64_decode(d["signed_identity_key"]["public"])
        }
        pre_key = {
            "keyPair": {
                "private": self._b64_decode(d["signed_pre_key"]["keyPair"]["private"]),
                "public": self._b64_decode(d["signed_pre_key"]["keyPair"]["public"])
            },
                "signature": self._b64_decode(d["signed_pre_key"]["signature"]),
                "keyId": d["signed_pre_key"]["keyId"]
        }
        adv_secret_key = d.get("adv_secret_key", "")
        if not isinstance(adv_secret_key, str):
            adv_secret_key = self._b64_encode(bytes(adv_secret_key))
        return AuthCreds(
            noise_key=noise_key,
            pairing_ephemeral_key_pair=pairing_key,
            signed_identity_key=id_key,
            signed_pre_key=pre_key,
            registration_id=d["registration_id"],
            adv_secret_key=adv_secret_key,
            processed_history_messages=d.get("processed_history_messages", []),
            next_pre_key_id=d.get("next_pre_key_id", 1),
            first_unuploaded_pre_key_id=d.get("first_unuploaded_pre_key_id", 1),
            account_sync_counter=d.get("account_sync_counter", 0),
            account_settings=d.get("account_settings", {"unarchive_chats": False}),
            registered=d.get("registered", False),
            pairing_code=d.get("pairing_code"),
            last_prop_hash=d.get("last_prop_hash"),
            routing_info=self._b64_decode(d["routing_info"]) if d.get("routing_info") else None,
            additional_data=d.get("additional_data"),
            account=d.get("account"),
            me=d.get("me"),
            server_hashes=d.get("server_hashes", []),
            signal_identities=d.get("signal_identities", []),
            platform=d.get("platform"),
        )

    async def get_creds(self) -> AuthCreds | None:
        await self.connect()
        async with self._db.execute('SELECT data FROM creds WHERE id=?', ("default",)) as cursor:
            row = await cursor.fetchone()
            if row:
                return self._json_to_creds(row[0])
            return None

    async def save_creds(self, creds: AuthCreds) -> None:
        await self.connect()
        async with self._lock:
            data = self._creds_to_json(creds)
            await self._db.execute(
                'INSERT OR REPLACE INTO creds (id, data) VALUES (?, ?)',
                ("default", data)
            )
            await self._db.commit()

    async def get_session(self, jid: str) -> bytes | None:
        await self.connect()
        async with self._db.execute('SELECT data FROM sessions WHERE jid=?', (jid,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return self._b64_decode(row[0])
            return None

    async def save_session(self, jid: str, data: bytes) -> None:
        await self.connect()
        async with self._lock:
            encoded = self._b64_encode(data)
            await self._db.execute(
                'INSERT OR REPLACE INTO sessions (jid, data) VALUES (?, ?)',
                (jid, encoded)
            )
            await self._db.commit()

    async def get_prekey(self, key_id: int) -> bytes | None:
        await self.connect()
        async with self._db.execute('SELECT data FROM prekeys WHERE key_id=?', (key_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return self._b64_decode(row[0])
            return None

    async def save_prekey(self, key_id: int, data: bytes) -> None:
        await self.connect()
        async with self._lock:
            encoded = self._b64_encode(data)
            await self._db.execute(
                'INSERT OR REPLACE INTO prekeys (key_id, data) VALUES (?, ?)',
                (key_id, encoded)
            )
            await self._db.commit()

    async def get_sender_key(self, group_jid: str, sender_jid: str) -> bytes | None:
        await self.connect()
        async with self._db.execute(
            'SELECT data FROM sender_keys WHERE group_jid=? AND sender_jid=?', 
            (group_jid, sender_jid)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return self._b64_decode(row[0])
            return None

    async def save_sender_key(self, group_jid: str, sender_jid: str, data: bytes) -> None:
        await self.connect()
        async with self._lock:
            encoded = self._b64_encode(data)
            await self._db.execute(
                'INSERT OR REPLACE INTO sender_keys (group_jid, sender_jid, data) VALUES (?, ?, ?)',
                (group_jid, sender_jid, encoded)
            )
            await self._db.commit()
