from waton.utils.lt_hash import compute_lt_hash

def test_lt_hash_matches_expected_vector() -> None:
    assert compute_lt_hash([b"a", b"b"]) == bytes.fromhex("11" * 32)
