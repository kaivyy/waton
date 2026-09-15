"""Media key derivation helpers."""

from __future__ import annotations

from waton.utils.crypto import hkdf, sha256


MEDIA_HKDF_KEY_MAPPING: dict[str, str] = {
    "image": "Image",
    "sticker": "Image",
    "document": "Document",
    "video": "Video",
    "ptv": "Video",
    "gif": "Video",
    "audio": "Audio",
    "ptt": "Audio",
    "history": "History",
    "md-msg-hist": "History",
    "md-app-state": "App State",
}


def derive_media_keys(media_key: bytes, media_type: str) -> dict[str, bytes]:
    type_label = MEDIA_HKDF_KEY_MAPPING.get(media_type, media_type.capitalize())
    info = f"WhatsApp {type_label} Keys".encode()
    expanded = hkdf(media_key, 112, bytes(32), info)
    return {
        "iv": expanded[:16],
        "cipher_key": expanded[16:48],
        "mac_key": expanded[48:80],
        "ref_key": expanded[80:112],
    }


def upload_once(data: bytes) -> str:
    digest = sha256(data).hex()
    return f"https://media.local/{digest}"


def verify_remote_checksum(url: str, data: bytes) -> bool:
    expected = sha256(data).hex()
    remote = url.rstrip("/").split("/")[-1]
    return remote == expected
