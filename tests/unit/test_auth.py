from base64 import b64decode

from waton.defaults.config import WA_NOISE_HEADER
from waton.utils.auth import init_auth_creds


def test_init_auth_creds_shapes() -> None:
    creds = init_auth_creds()

    assert len(creds.noise_key["private"]) == 32
    assert len(creds.noise_key["public"]) == 32
    assert len(creds.signed_identity_key["private"]) == 32
    assert len(creds.signed_identity_key["public"]) == 32

    signed_pre_key = creds.signed_pre_key
    assert len(signed_pre_key["keyPair"]["private"]) == 32
    assert len(signed_pre_key["keyPair"]["public"]) == 32
    assert len(signed_pre_key["signature"]) == 64
    assert signed_pre_key["keyId"] == 1

    assert 1 <= creds.registration_id <= 16380
    assert len(b64decode(creds.adv_secret_key.encode("utf-8"))) == 32
    assert creds.server_hashes == []
    assert creds.signal_identities == []


def test_noise_header_constant() -> None:
    assert WA_NOISE_HEADER == b"WA\x06\x03"
