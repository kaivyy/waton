from waton.protocol.protobuf.wire import _encode_len_delimited
from waton.utils.lt_hash import compute_lt_hash, decode_app_state_sync_key, update_lt_hash


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
