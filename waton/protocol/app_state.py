from waton.utils.lt_hash import compute_lt_hash

def apply_patch(state: dict, patch: dict) -> dict:
    items = dict(state.get("items", {}))
    if patch["op"] == "set":
        items[patch["key"]] = patch["value"]
    version = int(state.get("version", 0)) + 1
    new_hash = compute_lt_hash([f"{k}:{v}".encode() for k, v in sorted(items.items())])
    return {"items": items, "version": version, "hash": new_hash}
