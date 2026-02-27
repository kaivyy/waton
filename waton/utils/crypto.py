"""Crypto wrappers and helpers using the Rust extension."""
from __future__ import annotations

import os

try:
    import waton._crypto as _rust_crypto
except Exception as exc:  # pragma: no cover - exercised only when extension is missing
    raise ImportError(
        "waton._crypto extension is not available. "
        "For end users, install a prebuilt wheel (no Rust needed): `pip install waton`. "
        "If you are building from source, install Rust + maturin and run `maturin develop`."
    ) from exc


curve25519_generate_keypair = _rust_crypto.curve25519_generate_keypair
rust_shared_key = _rust_crypto.curve25519_shared_key
rust_sign = _rust_crypto.curve25519_sign
rust_verify = _rust_crypto.curve25519_verify
rust_aes_gcm_encrypt = _rust_crypto.aes_gcm_encrypt
rust_aes_gcm_decrypt = _rust_crypto.aes_gcm_decrypt
rust_aes_cbc_encrypt = _rust_crypto.aes_cbc_encrypt
rust_aes_cbc_decrypt = _rust_crypto.aes_cbc_decrypt
rust_hkdf = _rust_crypto.hkdf_sha256
rust_hmac = _rust_crypto.hmac_sha256
rust_sha256 = _rust_crypto.sha256_hash
rust_signal_process_prekey_bundle = _rust_crypto.signal_process_prekey_bundle
rust_signal_session_encrypt = _rust_crypto.signal_session_encrypt
rust_signal_session_decrypt_prekey = _rust_crypto.signal_session_decrypt_prekey
rust_signal_session_decrypt_whisper = _rust_crypto.signal_session_decrypt_whisper
rust_group_encrypt = _rust_crypto.group_encrypt
rust_group_decrypt = _rust_crypto.group_decrypt
def generate_keypair() -> dict[str, bytes]:
    """Generates a Curve25519 keypair."""
    return curve25519_generate_keypair()

def shared_key(private_key: bytes, public_key: bytes) -> bytes:
    """Computes Curve25519 DH shared secret."""
    return rust_shared_key(private_key, public_key)

def sign(private_key: bytes, message: bytes) -> bytes:
    """Signs a message using Curve25519-compatible signature semantics."""
    return rust_sign(private_key, message)

def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verifies a Curve25519-compatible signature."""
    return rust_verify(public_key, message, signature)

def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM encryption."""
    return rust_aes_gcm_encrypt(plaintext, key, iv, aad)

def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM decryption."""
    return rust_aes_gcm_decrypt(ciphertext, key, iv, aad)

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return rust_aes_cbc_encrypt(plaintext, key, iv)

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return rust_aes_cbc_decrypt(ciphertext, key, iv)

def hkdf(input_key: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    """HKDF-SHA256."""
    return rust_hkdf(input_key, length, salt, info)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256."""
    return rust_hmac(key, data)

def sha256(data: bytes) -> bytes:
    """SHA256 digest."""
    return rust_sha256(data)

def signal_process_prekey_bundle(
    session: bytes | None,
    identity_private: bytes,
    registration_id: int,
    remote_name: str,
    remote_device: int,
    remote_registration_id: int,
    remote_identity_key: bytes,
    signed_prekey_id: int,
    signed_prekey_public: bytes,
    signed_prekey_signature: bytes,
    prekey_id: int | None,
    prekey_public: bytes | None,
) -> bytes:
    """Injects/updates a Signal session from a remote pre-key bundle."""
    return rust_signal_process_prekey_bundle(
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        remote_registration_id,
        remote_identity_key,
        signed_prekey_id,
        signed_prekey_public,
        signed_prekey_signature,
        session,
        prekey_id,
        prekey_public,
    )

def signal_session_encrypt(
    session: bytes,
    identity_private: bytes,
    registration_id: int,
    remote_name: str,
    remote_device: int,
    plaintext: bytes,
) -> tuple[str, bytes, bytes]:
    """Encrypts payload with an existing Signal session."""
    result = rust_signal_session_encrypt(
        session,
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        plaintext,
    )
    return str(result["type"]), bytes(result["ciphertext"]), bytes(result["session"])

def signal_session_decrypt_prekey(
    session: bytes,
    identity_private: bytes,
    registration_id: int,
    remote_name: str,
    remote_device: int,
    prekey_id: int | None,
    prekey_private: bytes | None,
    signed_prekey_id: int,
    signed_prekey_private: bytes,
    ciphertext: bytes,
) -> dict[str, str | bytes]:
    """Decrypts a PreKeySignalMessage and returns type, plaintext, and updated session."""
    result = rust_signal_session_decrypt_prekey(
        session,
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        prekey_id,
        prekey_private,
        signed_prekey_id,
        signed_prekey_private,
        ciphertext,
    )
    return {"type": str(result["type"]), "ciphertext": bytes(result["ciphertext"]), "session": bytes(result["session"])}

def signal_session_decrypt_whisper(
    session: bytes,
    identity_private: bytes,
    registration_id: int,
    remote_name: str,
    remote_device: int,
    ciphertext: bytes,
) -> dict[str, str | bytes]:
    """Decrypts a SignalMessage and returns type, plaintext, and updated session."""
    result = rust_signal_session_decrypt_whisper(
        session,
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        ciphertext,
    )
    return {"type": str(result["type"]), "ciphertext": bytes(result["ciphertext"]), "session": bytes(result["session"])}

def generate_random_bytes(length: int = 32) -> bytes:
    """Generates random bytes."""
    return os.urandom(length)

def group_encrypt(sender_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    res = rust_group_encrypt(sender_key, plaintext)
    return bytes(res["ciphertext"]), bytes(res["next_key"])

def group_decrypt(sender_key: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:
    res = rust_group_decrypt(sender_key, ciphertext)
    return bytes(res["plaintext"]), bytes(res["next_key"])
