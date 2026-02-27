"""Group sender-key management for encrypted group messaging."""

from __future__ import annotations

import hashlib
import secrets
from base64 import b64decode, b64encode
from typing import TYPE_CHECKING

from waton.utils.crypto import group_decrypt, group_encrypt

if TYPE_CHECKING:
    from waton.utils.auth import StoragePort

SENDER_KEY_SIZE = 32
KEY_DERIVE_CONTEXT = b"waton-group-sender-key"


def _normalize_sender_key(key_material: bytes) -> bytes:
    if len(key_material) == SENDER_KEY_SIZE:
        return key_material
    return hashlib.sha256(KEY_DERIVE_CONTEXT + key_material).digest()


def _decode_distribution_payload(payload: bytes) -> bytes:
    """Decode sender-key distribution payload.

    Accepted forms:
    - raw bytes (hashed/normalized)
    - `b"v1:<base64>"` encoded key blob
    """
    if payload.startswith(b"v1:"):
        encoded = payload[3:]
        try:
            return b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError("invalid sender-key distribution encoding") from exc
    return payload


class GroupCipher:
    """Manages sender keys for encrypting/decrypting group messages.

    The key lifecycle mirrors the Baileys flow at a high level:
    - each participant has a sender key per group
    - every encrypt/decrypt rotates and persists key material
    - sender-key distribution can bootstrap or update stored key state
    """

    def __init__(self, group_jid: str, storage: StoragePort) -> None:
        self.group_jid = group_jid
        self.storage = storage

    async def _get_sender_key(self, participant_jid: str) -> bytes | None:
        key = await self.storage.get_sender_key(self.group_jid, participant_jid)
        if key is None:
            return None
        return _normalize_sender_key(key)

    async def _save_sender_key(self, participant_jid: str, key: bytes) -> None:
        await self.storage.save_sender_key(self.group_jid, participant_jid, _normalize_sender_key(key))

    async def _load_or_create_sender_key(self, sender_jid: str) -> bytes:
        key = await self._get_sender_key(sender_jid)
        if key is not None:
            return key
        # Fresh local sender key for first outbound message in a group session.
        created = secrets.token_bytes(SENDER_KEY_SIZE)
        await self._save_sender_key(sender_jid, created)
        return created

    async def encrypt(self, sender_jid: str, plaintext: bytes) -> bytes:
        """Encrypt a group message and rotate sender key state."""
        sender_key = await self._load_or_create_sender_key(sender_jid)
        ciphertext, next_sender_key = group_encrypt(sender_key, plaintext)
        await self._save_sender_key(sender_jid, next_sender_key)
        return ciphertext

    async def decrypt(self, author_jid: str, ciphertext: bytes) -> bytes:
        """Decrypt an incoming group message and rotate sender key state."""
        sender_key = await self._get_sender_key(author_jid)
        if sender_key is None:
            raise ValueError(f"No sender key found for {author_jid} in {self.group_jid}")
        plaintext, next_sender_key = group_decrypt(sender_key, ciphertext)
        await self._save_sender_key(author_jid, next_sender_key)
        return plaintext

    async def process_sender_key_distribution(self, author_jid: str, skmsg: bytes) -> None:
        """Process a sender-key distribution payload and persist it.

        For now the payload parser accepts either:
        - raw 32-byte sender keys
        - arbitrary payload bytes (deterministically hashed to 32-byte key)
        """
        if not skmsg:
            raise ValueError("sender-key distribution payload cannot be empty")
        key_material = _decode_distribution_payload(skmsg)
        derived_sender_key = _normalize_sender_key(key_material)
        await self._save_sender_key(author_jid, derived_sender_key)

    async def export_sender_key(self, participant_jid: str) -> bytes | None:
        """Return normalized sender key bytes for diagnostics/persistence tests."""
        return await self._get_sender_key(participant_jid)

    async def export_sender_key_distribution(self, participant_jid: str) -> bytes | None:
        """Return a `v1:<base64>` sender-key distribution payload."""
        key = await self._get_sender_key(participant_jid)
        if key is None:
            return None
        return b"v1:" + b64encode(key)

    async def import_sender_key(self, participant_jid: str, key_material: bytes) -> None:
        """Import externally provisioned sender key material."""
        if not key_material:
            raise ValueError("sender key material cannot be empty")
        await self._save_sender_key(participant_jid, key_material)

    async def has_sender_key(self, participant_jid: str) -> bool:
        """Check whether sender key exists for participant in this group."""
        return await self._get_sender_key(participant_jid) is not None
