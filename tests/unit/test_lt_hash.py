from waton.protocol.protobuf.wire import _encode_len_delimited
from waton.utils.lt_hash import (
    WA_PATCH_INTEGRITY,
    compute_lt_hash,
    decode_app_state_sync_key,
    generate_content_mac,
    generate_patch_mac,
    generate_snapshot_mac,
    make_lt_hash_generator,
    new_lt_hash_state,
    update_lt_hash,
)


def test_lt_hash_matches_expected_vector() -> None:
    assert compute_lt_hash([b"a", b"b"]) == bytes.fromhex(
        "10acc478f08bab146699831d80fde1dd48f0ea63590ee5ffb35d3818cc72dc40"
    )


def test_lt_hash_empty_vector_is_deterministic() -> None:
    assert compute_lt_hash([]) == bytes.fromhex(
        "38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca"
    )


def test_update_lt_hash_add_then_remove_returns_initial_state() -> None:
    initial = bytes(128)
    added = update_lt_hash(
        initial,
        [{"action": "set", "index": b"chat:1", "value": b"on", "key": b"k"}],
    )
    reverted = update_lt_hash(
        added,
        [{"action": "remove", "index": b"chat:1", "value": b"on", "key": b"k"}],
    )
    assert reverted == initial


def test_decode_app_state_sync_key_extracts_field_1() -> None:
    payload = _encode_len_delimited(1, b"\x01\x02\x03\x04")
    assert decode_app_state_sync_key(payload) == b"\x01\x02\x03\x04"


def test_wa_patch_integrity_addition_and_subtraction_invertibility() -> None:
    base = bytes(128)
    item_a = b"value-mac-a-32-bytes-00000000000"
    item_b = b"value-mac-b-32-bytes-00000000000"

    added = WA_PATCH_INTEGRITY.subtract_then_add(base, [], [item_a, item_b])
    assert added != base

    reverted = WA_PATCH_INTEGRITY.subtract_then_add(added, [item_a, item_b], [])
    assert reverted == base


def test_wa_patch_integrity_commutativity() -> None:
    base = bytes(128)
    item_a = b"value-mac-1"
    item_b = b"value-mac-2"

    hash_1 = WA_PATCH_INTEGRITY.subtract_then_add(base, [], [item_a, item_b])
    hash_2 = WA_PATCH_INTEGRITY.subtract_then_add(base, [], [item_b, item_a])
    assert hash_1 == hash_2


def test_make_lt_hash_generator_matching_baileys() -> None:
    state = new_lt_hash_state()
    gen = make_lt_hash_generator(state)

    # SET operation
    gen.mix({
        "index_mac": b"idx1",
        "value_mac": b"val1",
        "operation": 1,  # SET
    })
    res = gen.finish()
    import base64
    k1 = base64.b64encode(b"idx1").decode("ascii")
    assert k1 in res["index_value_map"]
    assert res["index_value_map"][k1]["value_mac"] == b"val1"

    # REMOVE without previous op should not throw
    gen2 = make_lt_hash_generator(state)
    gen2.mix({
        "index_mac": b"ghost",
        "value_mac": b"ghost_val",
        "operation": 2,  # REMOVE
    })
    res2 = gen2.finish()
    assert res2["hash"] == bytes(128)


def test_generate_snapshot_and_patch_mac() -> None:
    key = b"secret-key-32-bytes-long-padding"
    state_bytes = bytes(128)
    snap_mac = generate_snapshot_mac(state_bytes, version=1, name="critical_block", key=key)
    assert len(snap_mac) == 32

    patch_mac = generate_patch_mac(snap_mac, [b"val_mac_1", b"val_mac_2"], version=2, name="critical_block", key=key)
    assert len(patch_mac) == 32


def test_generate_content_mac() -> None:
    key = b"sync-action-content-mac-key-32b"
    content_mac = generate_content_mac(operation=1, data=b"action-protobuf-bytes", key_id=b"key-id", key=key)
    assert len(content_mac) == 32
