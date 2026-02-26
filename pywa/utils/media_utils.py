"""Media key derivation helpers."""

from __future__ import annotations

from pywa.utils.crypto import hkdf


def derive_media_keys(media_key: bytes, media_type: str) -> dict[str, bytes]:
    info = f"WhatsApp {media_type.capitalize()} Keys".encode("utf-8")
    expanded = hkdf(media_key, 112, bytes(32), info)
    return {
        "iv": expanded[:16],
        "cipher_key": expanded[16:48],
        "mac_key": expanded[48:80],
        "ref_key": expanded[80:112],
    }
