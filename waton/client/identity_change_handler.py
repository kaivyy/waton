from collections.abc import Mapping


def handle_identity_change(state: Mapping[str, object], jid: str) -> dict[str, object]:
    out = dict(state)
    out["session_stale"] = True
    out["stale_jid"] = jid
    return out
