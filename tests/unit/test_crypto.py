from pywa._crypto import (
    aes_gcm_encrypt, aes_gcm_decrypt,
    curve25519_generate_keypair, curve25519_shared_key,
    curve25519_sign, curve25519_verify,
    hkdf_sha256, hmac_sha256, sha256_hash,
    aes_cbc_encrypt, aes_cbc_decrypt,
)

def test_aes_gcm_roundtrip():
    key = bytes(32)
    iv = bytes(12)
    aad = b""
    plaintext = b"hello world"
    ct = aes_gcm_encrypt(plaintext, key, iv, aad)
    pt = aes_gcm_decrypt(ct, key, iv, aad)
    assert pt == plaintext

def test_curve25519_keypair():
    kp = curve25519_generate_keypair()
    assert len(kp["private"]) == 32
    assert len(kp["public"]) == 32

def test_curve25519_shared_key():
    kp1 = curve25519_generate_keypair()
    kp2 = curve25519_generate_keypair()
    s1 = curve25519_shared_key(kp1["private"], kp2["public"])
    s2 = curve25519_shared_key(kp2["private"], kp1["public"])
    assert s1 == s2


def test_curve25519_sign_verify():
    kp = curve25519_generate_keypair()
    msg = b"pairing-signature-test"
    sig = curve25519_sign(kp["private"], msg)
    assert len(sig) == 64
    assert curve25519_verify(kp["public"], msg, sig) is True
    assert curve25519_verify(kp["public"], b"wrong", sig) is False

def test_hkdf_sha256():
    result = hkdf_sha256(b"input", 32, b"salt" * 8, b"info")
    assert len(result) == 32

def test_hmac_sha256():
    result = hmac_sha256(b"key", b"data")
    assert len(result) == 32

def test_aes_cbc_roundtrip():
    key = bytes(32)
    iv = bytes(16)
    plaintext = b"hello world12345"  # 16 bytes
    ct = aes_cbc_encrypt(plaintext, key, iv)
    pt = aes_cbc_decrypt(ct, key, iv)
    assert pt == plaintext
