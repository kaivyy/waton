"""JSON-file storage backend for auth and signal state."""

from __future__ import annotations

import asyncio
import json
from base64 import b64decode, b64encode
from pathlib import Path
from typing import Any

from pywa.utils.auth import AuthCreds, StoragePort
from pywa.utils.crypto import generate_keypair


class JsonStorage(StoragePort):
    """Simple JSON-backed async storage implementation."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = asyncio.Lock()

    async def _read_state(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "creds": None,
                "sessions": {},
                "prekeys": {},
                "sender_keys": {},
            }
        raw = await asyncio.to_thread(self.path.read_text, "utf-8")
        data = json.loads(raw)
        return {
            "creds": data.get("creds"),
            "sessions": data.get("sessions", {}),
            "prekeys": data.get("prekeys", {}),
            "sender_keys": data.get("sender_keys", {}),
        }

    async def _write_state(self, state: dict[str, Any]) -> None:
        await asyncio.to_thread(self.path.parent.mkdir, parents=True, exist_ok=True)
        payload = json.dumps(state, separators=(",", ":"))
        await asyncio.to_thread(self.path.write_text, payload, "utf-8")

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        return b64encode(data).decode("utf-8")

    @staticmethod
    def _b64_decode(data: str) -> bytes:
        return b64decode(data.encode("utf-8"))

    def _creds_to_json(self, creds: AuthCreds) -> dict[str, Any]:
        return {
            "noise_key": {
                "private": self._b64_encode(creds.noise_key["private"]),
                "public": self._b64_encode(creds.noise_key["public"]),
            },
            "pairing_ephemeral_key_pair": {
                "private": self._b64_encode(creds.pairing_ephemeral_key_pair["private"]),
                "public": self._b64_encode(creds.pairing_ephemeral_key_pair["public"]),
            },
            "signed_identity_key": {
                "private": self._b64_encode(creds.signed_identity_key["private"]),
                "public": self._b64_encode(creds.signed_identity_key["public"]),
            },
            "signed_pre_key": {
                "keyPair": {
                    "private": self._b64_encode(creds.signed_pre_key["keyPair"]["private"]),
                    "public": self._b64_encode(creds.signed_pre_key["keyPair"]["public"]),
                },
                "signature": self._b64_encode(creds.signed_pre_key["signature"]),
                "keyId": creds.signed_pre_key["keyId"],
            },
            "registration_id": creds.registration_id,
            "adv_secret_key": creds.adv_secret_key,
            "processed_history_messages": creds.processed_history_messages,
            "next_pre_key_id": creds.next_pre_key_id,
            "first_unuploaded_pre_key_id": creds.first_unuploaded_pre_key_id,
            "account_sync_counter": creds.account_sync_counter,
            "account_settings": creds.account_settings,
            "registered": creds.registered,
            "pairing_code": creds.pairing_code,
            "last_prop_hash": creds.last_prop_hash,
            "routing_info": self._b64_encode(creds.routing_info) if creds.routing_info else None,
            "additional_data": creds.additional_data,
            "server_hashes": creds.server_hashes,
            "account": creds.account,
            "me": creds.me,
            "signal_identities": creds.signal_identities,
            "platform": creds.platform,
        }

    def _json_to_creds(self, data: dict[str, Any]) -> AuthCreds:
        pairing_ephemeral = data.get("pairing_ephemeral_key_pair")
        if pairing_ephemeral:
            pairing_key = {
                "private": self._b64_decode(pairing_ephemeral["private"]),
                "public": self._b64_decode(pairing_ephemeral["public"]),
            }
        else:
            pairing_key = generate_keypair()
        adv_secret_key = data.get("adv_secret_key", "")
        if not isinstance(adv_secret_key, str):
            adv_secret_key = self._b64_encode(bytes(adv_secret_key))
        return AuthCreds(
            noise_key={
                "private": self._b64_decode(data["noise_key"]["private"]),
                "public": self._b64_decode(data["noise_key"]["public"]),
            },
            pairing_ephemeral_key_pair=pairing_key,
            signed_identity_key={
                "private": self._b64_decode(data["signed_identity_key"]["private"]),
                "public": self._b64_decode(data["signed_identity_key"]["public"]),
            },
            signed_pre_key={
                "keyPair": {
                    "private": self._b64_decode(data["signed_pre_key"]["keyPair"]["private"]),
                    "public": self._b64_decode(data["signed_pre_key"]["keyPair"]["public"]),
                },
                "signature": self._b64_decode(data["signed_pre_key"]["signature"]),
                "keyId": data["signed_pre_key"]["keyId"],
            },
            registration_id=data["registration_id"],
            adv_secret_key=adv_secret_key,
            processed_history_messages=data.get("processed_history_messages", []),
            next_pre_key_id=data.get("next_pre_key_id", 1),
            first_unuploaded_pre_key_id=data.get("first_unuploaded_pre_key_id", 1),
            account_sync_counter=data.get("account_sync_counter", 0),
            account_settings=data.get("account_settings", {"unarchive_chats": False}),
            registered=data.get("registered", False),
            pairing_code=data.get("pairing_code"),
            last_prop_hash=data.get("last_prop_hash"),
            routing_info=self._b64_decode(data["routing_info"]) if data.get("routing_info") else None,
            additional_data=data.get("additional_data"),
            server_hashes=data.get("server_hashes", []),
            account=data.get("account"),
            me=data.get("me"),
            signal_identities=data.get("signal_identities", []),
            platform=data.get("platform"),
        )

    async def get_creds(self) -> AuthCreds | None:
        state = await self._read_state()
        raw = state.get("creds")
        if raw is None:
            return None
        return self._json_to_creds(raw)

    async def save_creds(self, creds: AuthCreds) -> None:
        async with self._lock:
            state = await self._read_state()
            state["creds"] = self._creds_to_json(creds)
            await self._write_state(state)

    async def get_session(self, jid: str) -> bytes | None:
        state = await self._read_state()
        data = state["sessions"].get(jid)
        if data is None:
            return None
        return self._b64_decode(data)

    async def save_session(self, jid: str, data: bytes) -> None:
        async with self._lock:
            state = await self._read_state()
            state["sessions"][jid] = self._b64_encode(data)
            await self._write_state(state)

    async def get_prekey(self, key_id: int) -> bytes | None:
        state = await self._read_state()
        data = state["prekeys"].get(str(key_id))
        if data is None:
            return None
        return self._b64_decode(data)

    async def save_prekey(self, key_id: int, data: bytes) -> None:
        async with self._lock:
            state = await self._read_state()
            state["prekeys"][str(key_id)] = self._b64_encode(data)
            await self._write_state(state)

    async def get_sender_key(self, group_jid: str, sender_jid: str) -> bytes | None:
        state = await self._read_state()
        bucket = state["sender_keys"].get(group_jid, {})
        data = bucket.get(sender_jid)
        if data is None:
            return None
        return self._b64_decode(data)

    async def save_sender_key(self, group_jid: str, sender_jid: str, data: bytes) -> None:
        async with self._lock:
            state = await self._read_state()
            bucket = state["sender_keys"].setdefault(group_jid, {})
            bucket[sender_jid] = self._b64_encode(data)
            await self._write_state(state)
