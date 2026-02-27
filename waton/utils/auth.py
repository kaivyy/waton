"""Authentication credentials and storage interface."""

from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class AuthCreds:
    noise_key: dict[str, bytes]
    pairing_ephemeral_key_pair: dict[str, bytes]
    signed_identity_key: dict[str, bytes]
    signed_pre_key: dict[str, Any]
    registration_id: int
    adv_secret_key: str
    processed_history_messages: list[dict[str, Any]] | None = None
    next_pre_key_id: int = 1
    first_unuploaded_pre_key_id: int = 1
    account_sync_counter: int = 0
    account_settings: dict[str, Any] | None = None
    registered: bool = False
    pairing_code: str | None = None
    last_prop_hash: str | None = None
    routing_info: bytes | None = None
    additional_data: dict[str, Any] | None = None
    account: dict[str, Any] | None = None
    me: dict[str, Any] | None = None
    signal_identities: list[dict[str, Any]] | None = None
    server_hashes: list[str] | None = None
    platform: str | None = None

    def __post_init__(self) -> None:
        if self.processed_history_messages is None:
            self.processed_history_messages = []
        if self.account_settings is None:
            self.account_settings = {"unarchive_chats": False}
        if self.signal_identities is None:
            self.signal_identities = []
        if self.server_hashes is None:
            self.server_hashes = []


def init_auth_creds() -> AuthCreds:
    from waton.utils.crypto import generate_keypair, generate_random_bytes, sign

    identity_key = generate_keypair()
    pre_key_id = 1
    pre_key = generate_keypair()
    pre_key_sig = sign(identity_key["private"], b"\x05" + pre_key["public"])

    signed_pre_key = {
        "keyPair": pre_key,
        "signature": pre_key_sig,
        "keyId": pre_key_id,
    }
    reg_id = int.from_bytes(generate_random_bytes(4), byteorder="big") % 16380 + 1

    return AuthCreds(
        noise_key=generate_keypair(),
        pairing_ephemeral_key_pair=generate_keypair(),
        signed_identity_key=identity_key,
        signed_pre_key=signed_pre_key,
        registration_id=reg_id,
        adv_secret_key=b64encode(generate_random_bytes(32)).decode("utf-8"),
    )


class StoragePort(Protocol):
    """Protocol defining the interface for all persistent state in waton."""

    async def get_creds(self) -> AuthCreds | None:
        ...

    async def save_creds(self, creds: AuthCreds) -> None:
        ...

    async def get_session(self, jid: str) -> bytes | None:
        ...

    async def save_session(self, jid: str, data: bytes) -> None:
        ...

    async def get_prekey(self, key_id: int) -> bytes | None:
        ...

    async def save_prekey(self, key_id: int, data: bytes) -> None:
        ...

    async def get_sender_key(self, group_jid: str, sender_jid: str) -> bytes | None:
        ...

    async def save_sender_key(self, group_jid: str, sender_jid: str, data: bytes) -> None:
        ...

