"""Noise handshake + transport framing compatible with WhatsApp Web flow."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from pywa.defaults.config import NOISE_MODE, WA_NOISE_HEADER
from pywa.protocol.binary_codec import decode_binary_node
from pywa.protocol.binary_node import BinaryNode
from pywa.utils.crypto import aes_decrypt, aes_encrypt, generate_keypair, hkdf, sha256, shared_key

EMPTY_AAD = b""


def _generate_iv(counter: int) -> bytes:
    iv = bytearray(12)
    iv[8:] = struct.pack(">I", counter)
    return bytes(iv)


@dataclass
class TransportState:
    enc_key: bytes
    dec_key: bytes
    read_counter: int = 0
    write_counter: int = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        out = aes_encrypt(plaintext, self.enc_key, _generate_iv(self.write_counter), EMPTY_AAD)
        self.write_counter += 1
        return out

    def decrypt(self, ciphertext: bytes) -> bytes:
        out = aes_decrypt(ciphertext, self.dec_key, _generate_iv(self.read_counter), EMPTY_AAD)
        self.read_counter += 1
        return out


class NoiseHandler:
    """Port of Baileys makeNoiseHandler semantics for pywa."""

    def __init__(
        self,
        keypair: dict[str, bytes] | None = None,
        noise_header: bytes = WA_NOISE_HEADER,
        routing_info: bytes | None = None,
    ):
        self.local_keypair = keypair or generate_keypair()
        self.noise_header = noise_header

        init_hash = NOISE_MODE if len(NOISE_MODE) == 32 else sha256(NOISE_MODE)
        self.hash = init_hash
        self.salt = init_hash
        self.enc_key = init_hash
        self.dec_key = init_hash
        self.counter = 0

        self.transport: TransportState | None = None
        self.is_waiting_for_transport = False

        self.sent_intro = False
        self.intro_header = self._build_intro_header(routing_info, noise_header)
        self.in_bytes = bytearray()

        self.authenticate(noise_header)
        self.authenticate(self.local_keypair["public"])

    @staticmethod
    def _build_intro_header(routing_info: bytes | None, noise_header: bytes) -> bytes:
        if not routing_info:
            return noise_header
        size = len(routing_info)
        header = bytearray(7 + size + len(noise_header))
        header[0:2] = b"ED"
        header[2] = 0
        header[3] = 1
        header[4] = (size >> 16) & 0xFF
        header[5] = (size >> 8) & 0xFF
        header[6] = size & 0xFF
        header[7 : 7 + size] = routing_info
        header[7 + size : 7 + size + len(noise_header)] = noise_header
        return bytes(header)

    def authenticate(self, data: bytes) -> None:
        if self.transport is None:
            self.hash = sha256(self.hash + data)

    def _hkdf(self, data: bytes) -> tuple[bytes, bytes]:
        key = hkdf(data, 64, self.salt, b"")
        return key[:32], key[32:]

    def mix_into_key(self, data: bytes) -> None:
        write, read = self._hkdf(data)
        self.salt = write
        self.enc_key = read
        self.dec_key = read
        self.counter = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.transport is not None:
            return self.transport.encrypt(plaintext)
        out = aes_encrypt(plaintext, self.enc_key, _generate_iv(self.counter), self.hash)
        self.counter += 1
        self.authenticate(out)
        return out

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.transport is not None:
            return self.transport.decrypt(ciphertext)
        out = aes_decrypt(ciphertext, self.dec_key, _generate_iv(self.counter), self.hash)
        self.counter += 1
        self.authenticate(ciphertext)
        return out

    def process_handshake(self, server_hello: Any, noise_key: dict[str, bytes]) -> bytes:
        """Process WA server hello and return encrypted static key payload."""
        server_ephemeral = bytes(server_hello.ephemeral or b"")
        if len(server_ephemeral) != 32:
            raise ValueError("invalid server hello: missing ephemeral key")
        self.authenticate(server_ephemeral)
        self.mix_into_key(shared_key(self.local_keypair["private"], server_ephemeral))

        dec_static = self.decrypt(bytes(server_hello.static or b""))
        if len(dec_static) != 32:
            raise ValueError("invalid server hello: bad static key")
        self.mix_into_key(shared_key(self.local_keypair["private"], dec_static))

        payload = bytes(server_hello.payload or b"")
        if payload:
            # Keep certificate payload parsing/verification optional in this layer.
            self.decrypt(payload)

        key_enc = self.encrypt(noise_key["public"])
        self.mix_into_key(shared_key(noise_key["private"], server_ephemeral))
        return key_enc

    def finish_init(self) -> None:
        self.is_waiting_for_transport = True
        write, read = self._hkdf(b"")
        self.transport = TransportState(enc_key=write, dec_key=read)
        self.is_waiting_for_transport = False

    def encode_frame(self, data: bytes) -> bytes:
        if self.transport is not None:
            data = self.transport.encrypt(data)
        intro = b"" if self.sent_intro else self.intro_header
        self.sent_intro = True
        size = len(data)
        header = bytes(((size >> 16) & 0xFF, (size >> 8) & 0xFF, size & 0xFF))
        return intro + header + data

    def decode_frame(self, new_data: bytes) -> list[bytes | BinaryNode]:
        if self.is_waiting_for_transport:
            self.in_bytes.extend(new_data)
            return []

        self.in_bytes.extend(new_data)
        out: list[bytes | BinaryNode] = []
        while True:
            if len(self.in_bytes) < 3:
                break
            size = (self.in_bytes[0] << 16) | (self.in_bytes[1] << 8) | self.in_bytes[2]
            if len(self.in_bytes) < size + 3:
                break
            frame = bytes(self.in_bytes[3 : size + 3])
            del self.in_bytes[: size + 3]

            if self.transport is not None:
                decrypted = self.transport.decrypt(frame)
                out.append(decode_binary_node(decrypted))
            else:
                out.append(frame)
        return out

    def encrypt_frame(self, plaintext: bytes) -> bytes:
        return self.encrypt(plaintext)

    def decrypt_frame(self, ciphertext: bytes) -> bytes:
        return self.decrypt(ciphertext)

