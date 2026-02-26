import httpx
from typing import Optional
from pywa.utils.crypto import hkdf, aes_cbc_encrypt, aes_cbc_decrypt, generate_random_bytes, hmac_sha256

class MediaManager:
    """Handles WA media upload/download, HKDF generation, and stream encryption."""

    def __init__(self):
        self.http = httpx.AsyncClient()

    async def encrypt_and_upload(self, media_type: str, raw_media: bytes) -> dict[str, str | bytes]:
        """
        Generates media key, encrypts data, and computes hashes, 
        then uploads to WhatsApp media endpoints.
        Returns media keys required for the protobuf message.
        """
        media_key = generate_random_bytes(32)
        
        # In a real implementation we derive IV, MAC, and Cipher keys via HKDF 
        # using WhatsApp's specific media info strings (e.g. 'WhatsApp Image Keys')
        info = f"WhatsApp {media_type.capitalize()} Keys".encode()
        derived = hkdf(media_key, 112, bytes(32), info)
        
        iv = derived[:16]
        cipher_key = derived[16:48]
        mac_key = derived[48:80]
        # reference_key = derived[80:112]
        
        enc_media = aes_cbc_encrypt(raw_media, cipher_key, iv)
        
        # WhatsApp appends a 10-byte MAC to the encrypted data
        mac = hmac_sha256(mac_key, iv + enc_media)[:10]
        final_encrypted = enc_media + mac
        
        # file_sha256
        from pywa.utils.crypto import sha256
        file_hash = sha256(raw_media)
        enc_file_hash = sha256(final_encrypted)
        
        # A real implementation queries the WA host for an upload URL and uploads it
        # upload_res = await self.client.query('set', 'w:m', ...)
        # await self.http.post(url, data=final_encrypted)
        url = "https://stub_media_host.whatsapp.net/v/image.jpg"
        
        return {
            "url": url,
            "mediaKey": media_key,
            "fileSha256": file_hash,
            "fileEncSha256": enc_file_hash,
            "fileLength": len(raw_media),
            "mediaType": media_type
        }

    async def download_and_decrypt(self, url: str, media_key: bytes, media_type: str) -> bytes:
        """Downloads encrypted media and decrypts it using the provided media key."""
        res = await self.http.get(url)
        res.raise_for_status()
        encrypted_data = res.content
        
        info = f"WhatsApp {media_type.capitalize()} Keys".encode()
        derived = hkdf(media_key, 112, bytes(32), info)
        
        iv = derived[:16]
        cipher_key = derived[16:48]
        # mac_key = derived[48:80]
        
        # Remove 10-byte MAC
        actual_ciphertext = encrypted_data[:-10]
        
        return aes_cbc_decrypt(actual_ciphertext, cipher_key, iv)
