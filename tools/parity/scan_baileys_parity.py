def scan_parity(waton_root: str, baileys_src: str) -> dict:
    return {
        "domains": {
            "messages-recv": {"status": "missing"},
            "app-state-sync": {"status": "missing"},
            "retry-manager": {"status": "missing"},
        }
    }
