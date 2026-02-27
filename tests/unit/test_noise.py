from waton.defaults.config import WA_NOISE_HEADER
from waton.protocol.noise_handler import NoiseHandler, TransportState
from waton.utils.crypto import generate_keypair


def test_noise_encode_frame_sends_intro_once() -> None:
    noise = NoiseHandler(generate_keypair())

    first = noise.encode_frame(b"abc")
    assert first.startswith(WA_NOISE_HEADER)
    assert first[len(WA_NOISE_HEADER) : len(WA_NOISE_HEADER) + 3] == b"\x00\x00\x03"

    second = noise.encode_frame(b"x")
    assert second[:3] == b"\x00\x00\x01"
    assert not second.startswith(WA_NOISE_HEADER)


def test_noise_decode_frame_before_transport() -> None:
    noise = NoiseHandler(generate_keypair())
    frames = noise.decode_frame(b"\x00\x00\x03abc")
    assert frames == [b"abc"]


def test_noise_handshake_phase_encrypt_decrypt_roundtrip() -> None:
    sender = NoiseHandler(generate_keypair())
    receiver = NoiseHandler(generate_keypair())

    sender.enc_key = bytes(32)
    sender.dec_key = bytes(32)
    sender.hash = bytes(32)
    sender.counter = 0

    receiver.enc_key = bytes(32)
    receiver.dec_key = bytes(32)
    receiver.hash = bytes(32)
    receiver.counter = 0

    ciphertext = sender.encrypt(b"hello world")
    plaintext = receiver.decrypt(ciphertext)
    assert plaintext == b"hello world"


def test_transport_state_roundtrip() -> None:
    sender = TransportState(enc_key=bytes(32), dec_key=bytes(32))
    receiver = TransportState(enc_key=bytes(32), dec_key=bytes(32))
    ciphertext = sender.encrypt(b"frame data")
    plaintext = receiver.decrypt(ciphertext)
    assert plaintext == b"frame data"

