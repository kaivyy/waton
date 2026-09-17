from __future__ import annotations

import base64
from waton.protocol.binary_node import BinaryNode
from waton.utils.chat_utils import (
    decode_syncd_snapshot,
    encode_syncd_patch,
    expand_app_state_keys,
    extract_syncd_patches,
    is_group_chat,
    is_private_chat,
    new_lt_hash_state,
    normalize_chat_jid,
)


def test_expand_app_state_keys_returns_five_32_byte_keys() -> None:
    key_data = b"0" * 32
    keys = expand_app_state_keys(key_data)

    assert set(keys.keys()) == {
        "index_key",
        "value_encryption_key",
        "value_mac_key",
        "snapshot_mac_key",
        "patch_mac_key",
    }
    for k, v in keys.items():
        assert len(v) == 32, f"Key {k} has invalid length {len(v)}"


def test_encode_syncd_patch_produces_encrypted_patch_and_state() -> None:
    key_data = b"k" * 32
    key_id = base64.b64encode(b"app-state-key-1").decode("ascii")
    state = new_lt_hash_state()

    patch_create = {
        "type": "regular_low",
        "index": ["mute", "123456@s.whatsapp.net"],
        "syncAction": {"muteAction": {"muted": True}},
        "apiVersion": 2,
        "operation": "set",
    }

    result = encode_syncd_patch(patch_create, key_id, state, key_data)
    assert "patch" in result
    assert "state" in result
    assert isinstance(result["patch"], bytes)
    assert len(result["patch"]) > 0

    new_state = result["state"]
    assert new_state["version"] == 1
    assert new_state["hash"] != state["hash"]
    assert len(new_state["index_value_map"]) == 1


def test_jid_helpers() -> None:
    assert is_group_chat("12345-67890@g.us") is True
    assert is_group_chat("12345@s.whatsapp.net") is False
    assert is_private_chat("12345@s.whatsapp.net") is True
    assert normalize_chat_jid("12345:2@s.whatsapp.net") == "12345@s.whatsapp.net"


def test_extract_syncd_patches() -> None:
    node = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="sync",
                attrs={},
                content=[
                    BinaryNode(
                        tag="collection",
                        attrs={"name": "critical_block", "version": "5", "has_more_patches": "true"},
                        content=[
                            BinaryNode(tag="patches", attrs={}, content=[
                                BinaryNode(tag="patch", attrs={}, content=b"patch-content-1")
                            ])
                        ],
                    )
                ],
            )
        ],
    )
    cols = extract_syncd_patches(node)
    assert "critical_block" in cols
    assert cols["critical_block"]["version"] == 5
    assert cols["critical_block"]["has_more_patches"] is True
    assert cols["critical_block"]["patches"] == [b"patch-content-1"]
