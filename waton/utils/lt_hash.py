"""Lightweight LT-hash style helpers for app-state sync integrity.

The real WhatsApp implementation uses a Rust anti-tampering hash. This module
keeps a deterministic Python version with the same high-level properties:
order-sensitive mutation folding and add/remove balancing over a lattice state.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from waton.protocol.protobuf.wire import _iter_fields

LT_HASH_STATE_SIZE = 128
LT_HASH_WORD_COUNT = LT_HASH_STATE_SIZE // 2
REMOVE_ACTIONS = {"delete", "remove", "unset"}


def _to_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def decode_app_state_sync_key(key_data: bytes) -> bytes:
    """Decode `AppStateSyncKeyData` and return the raw key bytes.

    WhatsApp proto:
    - field 1: `keyData` (bytes)
    - field 2: fingerprint
    - field 3: timestamp
    """
    for field_no, wire_type, value in _iter_fields(key_data):
        if field_no == 1 and wire_type == 2:
            return bytes(value)
    return b""


def generate_mutation_mac(action: str, index: bytes, value: bytes, key: bytes) -> bytes:
    """Return deterministic HMAC-SHA256 for one mutation.

    The action parameter is accepted for caller parity, but the digest itself is
    derived from index/value only so that add/remove can be inverses.
    """
    del action
    payload = b"\x00".join((index, value))
    return hmac.new(key, payload, hashlib.sha256).digest()


def update_lt_hash(current_hash: bytes, mutations: list[dict[str, Any]]) -> bytes:
    """Fold mutations into a 128-byte lattice state.

    Each mutation contributes a 32-byte MAC expanded across 64 uint16 words.
    Add actions increment words; remove actions decrement words (mod 2^16).
    """
    state = bytearray(current_hash or bytes(LT_HASH_STATE_SIZE))
    if len(state) != LT_HASH_STATE_SIZE:
        raise ValueError(f"lt-hash state must be {LT_HASH_STATE_SIZE} bytes")

    for mutation in mutations:
        action = str(mutation.get("action", "set")).lower()
        index = _to_bytes(mutation.get("index"))
        value = _to_bytes(mutation.get("value"))
        key = _to_bytes(mutation.get("key")) or b"lt-hash-default-key"

        mac = generate_mutation_mac(action, index, value, key)
        sign = -1 if action in REMOVE_ACTIONS else 1

        for i in range(LT_HASH_WORD_COUNT):
            pos = i * 2
            word = (state[pos] << 8) | state[pos + 1]
            delta = mac[i % len(mac)]
            next_word = (word + (sign * delta)) & 0xFFFF
            state[pos] = (next_word >> 8) & 0xFF
            state[pos + 1] = next_word & 0xFF

    return bytes(state)


def compute_lt_hash(items: list[bytes]) -> bytes:
    """Compute a compact 32-byte digest from folded lattice state."""
    if not items:
        return hashlib.sha256(bytes(LT_HASH_STATE_SIZE)).digest()

    mutations = [
        {
            "action": "set",
            "index": idx.to_bytes(4, "big"),
            "value": item,
            "key": b"lt-hash-default-key",
        }
        for idx, item in enumerate(items)
    ]
    state = update_lt_hash(bytes(LT_HASH_STATE_SIZE), mutations)
    return hashlib.sha256(state).digest()
