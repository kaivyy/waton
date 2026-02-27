"""Media key derivation helpers."""

from __future__ import annotations

from waton.utils.crypto import hkdf, sha256


def derive_media_keys(media_key: bytes, media_type: str) -> dict[str, bytes]:
    info = f"WhatsApp {media_type.capitalize()} Keys".encode()
    expanded = hkdf(media_key, 112, bytes(32), info)
    return {
        "iv": expanded[:16],
        "cipher_key": expanded[16:48],
        "mac_key": expanded[48:80],
        "ref_key": expanded[80:112],
    }

def _upload_once(data: bytes) -> str:
    digest = sha256(data).hex()
    return f"https://media.local/{digest}"

def _verify_remote_checksum(url: str, data: bytes) -> bool:
    expected = sha256(data).hex()
    remote = url.rstrip("/").split("/")[-1]
    return remote == expected
