"""LT-Hash implementation for WhatsApp app-state sync integrity.

WhatsApp uses a lattice-based homomorphic hashing algorithm (LT-Hash) over
128-byte states (64 x uint16 little-endian words, mod 2^16).
Reference:
- whatsmeow: appstate/lthash/lthash.go
- Baileys: whatsapp-rust-bridge / LTHashAntiTampering
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
from typing import Any

from waton.protocol.protobuf.wire import iter_wire_fields
from waton.utils.crypto import hkdf, hmac_sha256

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
    for field_no, wire_type, value in iter_wire_fields(key_data):
        if field_no == 1 and wire_type == 2:
            return bytes(value)
    return b""


class LTHash:
    """Homomorphic summation-based hash for app state sync patch integrity."""

    def __init__(
        self,
        hkdf_info: bytes = b"WhatsApp Patch Integrity",
        hkdf_size: int = 128,
    ) -> None:
        self.hkdf_info = hkdf_info
        self.hkdf_size = hkdf_size

    def subtract_then_add(
        self,
        base: bytes,
        subtract: list[bytes],
        add: list[bytes],
    ) -> bytes:
        state = bytearray(base if len(base) == LT_HASH_STATE_SIZE else bytes(LT_HASH_STATE_SIZE))
        self.subtract_then_add_in_place(state, subtract, add)
        return bytes(state)

    def subtract_then_add_in_place(
        self,
        base: bytearray,
        subtract: list[bytes],
        add: list[bytes],
    ) -> None:
        self._multiple_op(base, subtract, subtract=True)
        self._multiple_op(base, add, subtract=False)

    def _multiple_op(
        self,
        base: bytearray,
        items: list[bytes],
        *,
        subtract: bool,
    ) -> None:
        for item in items:
            expanded = hkdf(item, self.hkdf_size, b"", self.hkdf_info)
            self._perform_pointwise_with_overflow(base, expanded, subtract=subtract)

    @staticmethod
    def _perform_pointwise_with_overflow(
        base: bytearray,
        delta: bytes,
        *,
        subtract: bool,
    ) -> None:
        base_words = list(struct.unpack("<64H", base))
        delta_words = struct.unpack("<64H", delta)
        if subtract:
            for i in range(64):
                base_words[i] = (base_words[i] - delta_words[i]) & 0xFFFF
        else:
            for i in range(64):
                base_words[i] = (base_words[i] + delta_words[i]) & 0xFFFF
        base[:] = struct.pack("<64H", *base_words)


WA_PATCH_INTEGRITY = LTHash()


def new_lt_hash_state() -> dict[str, Any]:
    """Returns an empty LTHash state dictionary."""
    return {"version": 0, "hash": bytes(LT_HASH_STATE_SIZE), "index_value_map": {}}


def make_lt_hash_generator(state: dict[str, Any]) -> Any:
    """Stateful LT-hash generator matching Baileys makeLtHashGenerator."""
    current_hash = state.get("hash") or bytes(LT_HASH_STATE_SIZE)
    if isinstance(current_hash, bytearray):
        current_hash = bytes(current_hash)
    index_value_map = dict(state.get("index_value_map") or state.get("indexValueMap") or {})
    add_buffs: list[bytes] = []
    sub_buffs: list[bytes] = []

    class _Generator:
        def mix(self, item: dict[str, Any]) -> None:
            index_mac = _to_bytes(item.get("index_mac") or item.get("indexMac"))
            value_mac = _to_bytes(item.get("value_mac") or item.get("valueMac"))
            operation = item.get("operation")
            # Operation 1 is SET, 2 is REMOVE (or string equivalents)
            is_remove = operation in (2, "remove", "REMOVE")

            index_b64 = base64.b64encode(index_mac).decode("ascii")
            prev_op = index_value_map.get(index_b64)

            if is_remove:
                if not prev_op:
                    # WhatsApp Web skips missing remove without throwing
                    return
                index_value_map.pop(index_b64, None)
            else:
                add_buffs.append(value_mac)
                index_value_map[index_b64] = {"value_mac": value_mac}

            if prev_op:
                prev_val = prev_op.get("value_mac") or prev_op.get("valueMac")
                if prev_val:
                    sub_buffs.append(_to_bytes(prev_val))

        def finish(self) -> dict[str, Any]:
            result_hash = WA_PATCH_INTEGRITY.subtract_then_add(current_hash, sub_buffs, add_buffs)
            return {
                "hash": result_hash,
                "index_value_map": index_value_map,
                "indexValueMap": index_value_map,
            }

    return _Generator()


def generate_snapshot_mac(
    lthash_state: bytes,
    version: int,
    name: str,
    key: bytes,
) -> bytes:
    """Generates HMAC-SHA256 snapshot MAC."""
    payload = lthash_state + version.to_bytes(8, "big") + name.encode("utf-8")
    return hmac_sha256(key, payload)


def generate_patch_mac(
    snapshot_mac: bytes,
    value_macs: list[bytes],
    version: int,
    name: str,
    key: bytes,
) -> bytes:
    """Generates HMAC-SHA256 patch MAC."""
    payload = snapshot_mac + b"".join(value_macs) + version.to_bytes(8, "big") + name.encode("utf-8")
    return hmac_sha256(key, payload)


def generate_content_mac(
    operation: int,
    data: bytes,
    key_id: bytes,
    key: bytes,
) -> bytes:
    """Generates 32-byte HMAC-SHA512 content MAC."""
    op_byte = bytes([operation + 1])
    key_len_bytes = (len(key_id) + 1).to_bytes(8, "big")
    payload = op_byte + key_id + data + key_len_bytes
    return hmac.new(key, payload, hashlib.sha512).digest()[:32]


def generate_mutation_mac(action: str, index: bytes, value: bytes, key: bytes) -> bytes:
    """Return deterministic HMAC-SHA256 for one mutation (legacy helper)."""
    del action
    payload = b"\x00".join((index, value))
    return hmac.new(key, payload, hashlib.sha256).digest()


def update_lt_hash(current_hash: bytes, mutations: list[dict[str, Any]]) -> bytes:
    """Fold mutations into a 128-byte lattice state (legacy helper)."""
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
    """Compute a compact 32-byte digest from folded lattice state (legacy helper)."""
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
