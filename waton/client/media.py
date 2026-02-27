from __future__ import annotations

import httpx

from waton.utils.crypto import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    generate_random_bytes,
    hkdf,
    hmac_sha256,
    sha256,
)
from waton.utils.media_utils import _upload_once, _verify_remote_checksum


class MediaManager:
    """Handles media encryption, upload and decryption helpers."""

    def __init__(self) -> None:
        self.http = httpx.AsyncClient()

    async def encrypt_and_upload(self, media_type: str, raw_media: bytes) -> dict[str, str | bytes]:
        """
        Encrypt media payload, upload encrypted bytes, and return message metadata.
        """
        media_key = generate_random_bytes(32)

        info = f"WhatsApp {media_type.capitalize()} Keys".encode()
        derived = hkdf(media_key, 112, bytes(32), info)

        iv = derived[:16]
        cipher_key = derived[16:48]
        mac_key = derived[48:80]

        enc_media = aes_cbc_encrypt(raw_media, cipher_key, iv)
        mac = hmac_sha256(mac_key, iv + enc_media)[:10]
        final_encrypted = enc_media + mac

        file_hash = sha256(raw_media)
        enc_file_hash = sha256(final_encrypted)
        upload_result = upload_with_retry(final_encrypted)

        return {
            "url": upload_result["url"],
            "mediaKey": media_key,
            "fileSha256": file_hash,
            "fileEncSha256": enc_file_hash,
            "fileLength": len(raw_media),
            "mediaType": media_type,
        }

    async def download_and_decrypt(self, url: str, media_key: bytes, media_type: str) -> bytes:
        """Downloads encrypted media and decrypts it using media key."""
        res = await self.http.get(url)
        res.raise_for_status()
        encrypted_data = res.content

        info = f"WhatsApp {media_type.capitalize()} Keys".encode()
        derived = hkdf(media_key, 112, bytes(32), info)

        iv = derived[:16]
        cipher_key = derived[16:48]

        actual_ciphertext = encrypted_data[:-10]
        return aes_cbc_decrypt(actual_ciphertext, cipher_key, iv)


def upload_with_retry(data: bytes, max_attempts: int = 3) -> dict[str, str | int | bool]:
    for attempt in range(1, max_attempts + 1):
        url = _upload_once(data)
        if _verify_remote_checksum(url, data):
            return {"url": url, "attempts": attempt, "verified": True}
    raise RuntimeError("upload failed after retries")
