from collections.abc import Mapping
from typing import cast

from waton.utils.lt_hash import compute_lt_hash


def apply_patch(state: Mapping[str, object], patch: Mapping[str, object]) -> dict[str, object]:
    raw_items = state.get("items", {})
    items: dict[str, object]
    if isinstance(raw_items, Mapping):
        typed_items = cast("Mapping[str, object]", raw_items)
        items = {str(key): value for key, value in typed_items.items()}
    else:
        items = {}

    if patch.get("op") == "set":
        key = patch.get("key")
        if isinstance(key, str):
            items[key] = patch.get("value")

    version_raw = state.get("version", 0)
    version = int(version_raw) if isinstance(version_raw, (int, float, str)) else 0
    version += 1
    new_hash = compute_lt_hash([f"{k}:{v}".encode() for k, v in sorted(items.items())])
    return {"items": items, "version": version, "hash": new_hash}
