"""Chat JID and App State Syncd helper functions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable
import zlib

from waton.core.jid import is_jid_group, is_jid_user, jid_decode, jid_encode
from waton.protocol.binary_node import BinaryNode
from waton.utils.lt_hash import (
    generate_content_mac,
    generate_patch_mac,
    generate_snapshot_mac,
    make_lt_hash_generator,
    new_lt_hash_state,
)

if TYPE_CHECKING:
    from waton.protocol.binary_node import BinaryNode

__all__ = [
    "decode_syncd_snapshot",
    "download_external_blob",
    "encode_syncd_patch",
    "expand_app_state_keys",
    "extract_syncd_patches",
    "generate_content_mac",
    "generate_patch_mac",
    "generate_snapshot_mac",
    "is_group_chat",
    "is_private_chat",
    "make_lt_hash_generator",
    "new_lt_hash_state",
    "normalize_chat_jid",
]




def is_group_chat(jid: str) -> bool:
    return is_jid_group(jid)


def is_private_chat(jid: str) -> bool:
    return is_jid_user(jid)


def normalize_chat_jid(jid: str) -> str:
    decoded = jid_decode(jid)
    if decoded is None:
        return jid
    return jid_encode(decoded.user, decoded.server)


def extract_syncd_patches(result: BinaryNode) -> dict[str, dict[str, Any]]:
    """
    Extracts Syncd patches and snapshot nodes from an app-state sync IQ response.
    Mirrors Baileys `extractSyncdPatches`.
    """
    collections: dict[str, dict[str, Any]] = {}
    sync_node = _find_child(result, "sync")
    if not sync_node or not isinstance(sync_node.content, list):
        return collections

    for col in sync_node.content:
        if not isinstance(col, BinaryNode) or col.tag != "collection":
            continue

        name = col.attrs.get("name", "")
        has_more = col.attrs.get("has_more_patches") == "true"
        patches_node = _find_child(col, "patches")
        patch_nodes = _find_children(patches_node or col, "patch")

        snapshot_node = _find_child(col, "snapshot")
        snapshot_data = None
        if snapshot_node and snapshot_node.content is not None:
            snapshot_data = snapshot_node.content

        collections[name] = {
            "has_more_patches": has_more,
            "version": int(col.attrs.get("version", "0")),
            "patches": [p.content for p in patch_nodes if p.content is not None],
            "snapshot": snapshot_data,
        }

    return collections


async def download_external_blob(
    external_blob: dict[str, Any],
    download_fn: Callable[..., Any],
) -> bytes:
    """
    Downloads and decompresses an external MMS syncd patch/snapshot blob.
    Mirrors Baileys `downloadExternalBlob`.
    """
    direct_path = external_blob.get("directPath") or external_blob.get("direct_path", "")
    media_key = external_blob.get("mediaKey") or external_blob.get("media_key")
    data = await download_fn(direct_path, media_key, "md-app-state")
    try:
        return zlib.decompress(data)
    except Exception:
        return data


def decode_syncd_snapshot(snapshot_data: bytes) -> dict[str, Any]:
    """
    Decodes a Syncd snapshot binary payload.
    """
    from waton.protocol.protobuf.wire import iter_fields

    records: list[Any] = []
    version = 0
    mac = b""
    key_id = b""
    for field_no, wire_type, value in iter_fields(snapshot_data):
        if field_no == 1:
            if wire_type == 0:
                version = int(value)
            elif wire_type == 2:
                for sub_field, sub_wire, sub_val in iter_fields(bytes(value)):
                    if sub_field == 1 and sub_wire == 0:
                        version = int(sub_val)
        elif field_no == 2 and wire_type == 2:
            records.append(bytes(value))
        elif field_no == 3 and wire_type == 2:
            mac = bytes(value)
        elif field_no == 4 and wire_type == 2:
            key_id = bytes(value)

    return {
        "version": version,
        "records": records,
        "mac": mac,
        "key_id": key_id,
    }



def _find_child(node: BinaryNode | None, tag: str) -> BinaryNode | None:
    if node is None or not isinstance(node.content, list):
        return None
    for child in node.content:
        if isinstance(child, BinaryNode) and child.tag == tag:
            return child
    return None


def _find_children(node: BinaryNode | None, tag: str) -> list[BinaryNode]:
    if node is None or not isinstance(node.content, list):
        return []
    return [child for child in node.content if isinstance(child, BinaryNode) and child.tag == tag]


def expand_app_state_keys(key_data: bytes) -> dict[str, bytes]:
    """Derives the 5 mutation keys from an AppStateSyncKey using HKDF-SHA256.

    Mirrors Baileys `expandAppStateKeys` and whatsmeow `expandAppStateKeys`.
    Info: "WhatsApp Mutation Keys", Length: 160 bytes.
    """
    from waton.utils.crypto import hkdf

    expanded = hkdf(key_data, 160, b"", b"WhatsApp Mutation Keys")
    return {
        "index_key": expanded[0:32],
        "value_encryption_key": expanded[32:64],
        "value_mac_key": expanded[64:96],
        "snapshot_mac_key": expanded[96:128],
        "patch_mac_key": expanded[128:160],
    }


def encode_syncd_patch(
    patch_create: dict[str, Any],
    my_app_state_key_id: str | bytes,
    state: dict[str, Any],
    key_data: bytes,
) -> dict[str, Any]:
    """Encodes and encrypts a Syncd mutation patch ready to be transmitted in an IQ.

    Mirrors Baileys `encodeSyncdPatch`.
    """
    import base64
    import json
    import os
    from waton.protocol.protobuf.wire import encode_len_delimited, encode_varint_field
    from waton.utils.crypto import aes_cbc_encrypt, hmac_sha256

    patch_type = str(patch_create.get("type", "regular_low"))
    index = patch_create.get("index", [])
    sync_action = patch_create.get("syncAction") or patch_create.get("sync_action", {})
    api_version = int(patch_create.get("apiVersion", patch_create.get("api_version", 1)))
    operation_str = str(patch_create.get("operation", "set")).lower()
    operation_code = 1 if operation_str in ("remove", "delete") else 0  # 0=SET, 1=REMOVE

    enc_key_id = (
        base64.b64decode(my_app_state_key_id)
        if isinstance(my_app_state_key_id, str)
        else my_app_state_key_id
    )

    keys = expand_app_state_keys(key_data)

    index_buffer = json.dumps(index, separators=(",", ":")).encode("utf-8")
    action_data_bytes = json.dumps(sync_action, separators=(",", ":")).encode("utf-8")
    data_proto = b"".join(
        (
            encode_len_delimited(1, index_buffer),
            encode_len_delimited(2, action_data_bytes),
            encode_varint_field(4, api_version),
        )
    )

    random_iv = os.urandom(16)
    enc_value = random_iv + aes_cbc_encrypt(data_proto, keys["value_encryption_key"], random_iv)

    value_mac = generate_content_mac(operation_code, enc_value, enc_key_id, keys["value_mac_key"])
    index_mac = hmac_sha256(keys["index_key"], index_buffer)

    generator = make_lt_hash_generator(state)
    generator.mix({
        "index_mac": index_mac,
        "value_mac": value_mac,
        "operation": operation_code + 1,  # 1=SET, 2=REMOVE in generator
    })
    finished = generator.finish()
    new_state = {
        "version": state.get("version", 0) + 1,
        "hash": finished["hash"],
        "index_value_map": finished["index_value_map"],
    }

    snapshot_mac = generate_snapshot_mac(
        new_state["hash"],
        new_state["version"],
        patch_type,
        keys["snapshot_mac_key"],
    )
    patch_mac = generate_patch_mac(
        snapshot_mac,
        [value_mac],
        new_state["version"],
        patch_type,
        keys["patch_mac_key"],
    )

    record_bytes = b"".join(
        (
            encode_len_delimited(1, index_mac),
            encode_len_delimited(2, enc_value + value_mac),
            encode_len_delimited(3, enc_key_id),
        )
    )
    mutation_bytes = b"".join(
        (
            encode_varint_field(1, operation_code),
            encode_len_delimited(2, record_bytes),
            encode_len_delimited(3, enc_key_id),
        )
    )
    patch_wire = b"".join(
        (
            encode_len_delimited(1, encode_varint_field(1, new_state["version"])),
            encode_len_delimited(2, mutation_bytes),
            encode_len_delimited(4, snapshot_mac),
            encode_len_delimited(5, patch_mac),
            encode_len_delimited(6, enc_key_id),
        )
    )

    return {
        "patch": patch_wire,
        "state": new_state,
    }

