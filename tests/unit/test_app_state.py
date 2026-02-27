from waton.protocol.app_state import apply_patch

def test_apply_patch_updates_version_and_hash() -> None:
    state = {"version": 1, "hash": b"\x00" * 32}
    out = apply_patch(state, {"op": "set", "key": "chat:1", "value": "x"})
    assert out["version"] == 2
    assert out["hash"] != state["hash"]
