from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
from typing import Any
import io

import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

from waton.utils.crypto import generate_random_bytes
from waton.utils.media_utils import derive_media_keys


async def download_media_to_file(
    url: str,
    media_key: bytes,
    media_type: str,
    target_file_path: str,
    chunk_size: int = 65536,
) -> dict[str, Any]:
    keys = derive_media_keys(media_key, media_type)
    iv = keys["iv"]
    cipher_key = keys["cipher_key"]
    mac_key = keys["mac_key"]

    cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    sha256_hash = hashlib.sha256()
    hmac_hash = hmac.new(mac_key, iv, hashlib.sha256)
    
    size = 0
    buffer = b""

    async with httpx.AsyncClient() as client:
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            with open(target_file_path, "wb") as f:
                async for chunk in response.aiter_bytes(chunk_size=chunk_size):
                    buffer += chunk
                    process_len = len(buffer) - 26
                    if process_len >= 16:
                        blocks_len = (process_len // 16) * 16
                        process_chunk = buffer[:blocks_len]
                        buffer = buffer[blocks_len:]
                        
                        hmac_hash.update(process_chunk)
                        decrypted = decryptor.update(process_chunk)
                        sha256_hash.update(decrypted)
                        f.write(decrypted)
                        size += len(decrypted)
                
                if (len(buffer) - 10) % 16 != 0:
                    raise ValueError(f"Invalid remaining buffer length: {len(buffer)}")
                
                last_blocks = buffer[:-10]
                mac = buffer[-10:]
                
                if last_blocks:
                    hmac_hash.update(last_blocks)
                    decrypted = decryptor.update(last_blocks) + decryptor.finalize()
                    
                    pad_len = decrypted[-1]
                    if pad_len > 16 or pad_len == 0:
                        raise ValueError("Invalid PKCS7 padding")
                    
                    decrypted = decrypted[:-pad_len]
                    if decrypted:
                        sha256_hash.update(decrypted)
                        f.write(decrypted)
                        size += len(decrypted)
                
                expected_mac = hmac_hash.digest()[:10]
                if not hmac.compare_digest(expected_mac, mac):
                    raise ValueError("MAC mismatch")

    return {
        "file_path": target_file_path,
        "file_size": size,
        "sha256": sha256_hash.digest().hex(),
    }


def encrypt_file_to_temp(
    source_file_path: str,
    media_type: str,
    chunk_size: int = 65536,
) -> dict[str, Any]:
    media_key = generate_random_bytes(32)
    keys = derive_media_keys(media_key, media_type)
    iv = keys["iv"]
    cipher_key = keys["cipher_key"]
    mac_key = keys["mac_key"]

    cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    sha256_hash = hashlib.sha256()
    enc_sha256_hash = hashlib.sha256()
    hmac_hash = hmac.new(mac_key, iv, hashlib.sha256)

    fd, temp_file_path = tempfile.mkstemp(prefix="waton_media_")
    
    file_length = 0
    buffer = b""
    with open(source_file_path, "rb") as src, os.fdopen(fd, "wb") as dst:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
                
            file_length += len(chunk)
            sha256_hash.update(chunk)
            buffer += chunk
            
            if len(buffer) >= 16:
                blocks_len = (len(buffer) // 16) * 16
                process_chunk = buffer[:blocks_len]
                buffer = buffer[blocks_len:]
                
                encrypted = encryptor.update(process_chunk)
                enc_sha256_hash.update(encrypted)
                hmac_hash.update(encrypted)
                dst.write(encrypted)
        
        # PKCS7 padding
        pad_len = 16 - (len(buffer) % 16)
        buffer += bytes([pad_len] * pad_len)
        
        encrypted = encryptor.update(buffer) + encryptor.finalize()
        enc_sha256_hash.update(encrypted)
        hmac_hash.update(encrypted)
        dst.write(encrypted)
        
        mac = hmac_hash.digest()[:10]
        enc_sha256_hash.update(mac)
        dst.write(mac)
        
    return {
        "temp_file_path": temp_file_path,
        "file_length": file_length,
        "file_sha256": sha256_hash.digest(),
        "file_enc_sha256": enc_sha256_hash.digest(),
        "media_key": media_key,
    }

def extract_image_thumb(image_bytes: bytes, max_size: int = 32) -> bytes:
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            img.thumbnail((max_size, max_size))
            if img.mode != "RGB":
                img = img.convert("RGB")
            out = io.BytesIO()
            img.save(out, format="JPEG", quality=50)
            return out.getvalue()
    except Exception:
        return b""
