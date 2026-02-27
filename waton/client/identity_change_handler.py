def handle_identity_change(state: dict, jid: str) -> dict:
    out = dict(state)
    out["session_stale"] = True
    out["stale_jid"] = jid
    return out
