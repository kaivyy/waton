"""Generic utility helpers for cryptographic identifiers, encoding, and collections."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Iterable

T = TypeVar("T")

CROCKFORD_CHARACTERS = "123456789ABCDEFGHJKLMNPQRSTVWXYZ"


def first_or_none(values: Iterable[T]) -> T | None:
    for item in values:
        return item
    return None


def chunked(values: list[T], size: int) -> list[list[T]]:
    if size <= 0:
        raise ValueError("size must be > 0")
    return [values[i : i + size] for i in range(0, len(values), size)]


def ensure_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def encode_big_endian(value: int, width: int = 4) -> bytes:
    """Encode an integer as big-endian bytes of specified width."""
    return int(value).to_bytes(width, byteorder="big", signed=False)


def unix_timestamp_seconds() -> int:
    """Return current Unix timestamp in whole seconds."""
    return int(time.time())


def generate_participant_hash_v2(participants: list[str]) -> str:
    """Generate participant list hash v2 for group/DM routing deduplication."""
    sorted_parts = sorted(participants)
    joined = "".join(sorted_parts).encode("utf-8")
    sha256_hash = hashlib.sha256(joined).digest()
    b64 = base64.b64encode(sha256_hash).decode("ascii")
    return "2:" + b64[:6]


def generate_message_id_v2(user_id: str | None = None) -> str:
    """Generate a modern WhatsApp-compatible message ID prefixed with 3EB0."""
    ts = int(time.time()).to_bytes(8, byteorder="big")
    user_part = b""
    if user_id:
        user = user_id.split("@")[0].split(":")[0]
        user_part = f"{user}@c.us".encode("utf-8")
    user_buf = user_part.ljust(20, b"\x00")[:20]
    rand = secrets.token_bytes(16)
    data = ts + user_buf + rand
    h = hashlib.sha256(data).digest()
    return "3EB0" + h.hex().upper()[:18]


def bytes_to_crockford(data: bytes) -> str:
    """Encode bytes into Crockford Base32 representation."""
    value = 0
    bit_count = 0
    crockford: list[str] = []

    for byte in data:
        value = (value << 8) | (byte & 0xFF)
        bit_count += 8

        while bit_count >= 5:
            idx = (value >> (bit_count - 5)) & 31
            crockford.append(CROCKFORD_CHARACTERS[idx])
            bit_count -= 5

    if bit_count > 0:
        idx = (value << (5 - bit_count)) & 31
        crockford.append(CROCKFORD_CHARACTERS[idx])

    return "".join(crockford)
