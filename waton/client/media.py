from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

import httpx

from waton.utils.crypto import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    generate_random_bytes,
    hkdf,
    hmac_sha256,
    sha256,
)
from waton.utils.media_utils import upload_once, verify_remote_checksum


class MediaManager:
    """Handles media encryption, upload and decryption helpers."""

    def __init__(self) -> None:
        self.http = httpx.AsyncClient()

    @staticmethod
    def _force_ip_connect_transport(*, host: str, resolved_ip: str) -> httpx.AsyncBaseTransport:
        class _ResolvedIPTransport(httpx.AsyncBaseTransport):
            def __init__(self, *, resolved_ip: str, host: str) -> None:
                self._resolved_ip = resolved_ip
                self._host = host
                self._inner = httpx.AsyncHTTPTransport()

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                rewritten_url = request.url.copy_with(host=self._resolved_ip)
                headers = dict(request.headers)
                headers["host"] = self._host
                extensions = dict(request.extensions)
                extensions["sni_hostname"] = self._host
                rewritten_request = httpx.Request(
                    method=request.method,
                    url=rewritten_url,
                    headers=headers,
                    content=request.stream,
                    extensions=extensions,
                )
                return await self._inner.handle_async_request(rewritten_request)

            async def aclose(self) -> None:
                await self._inner.aclose()

        return _ResolvedIPTransport(resolved_ip=resolved_ip, host=host)

    @classmethod
    def _validated_endpoint(cls, url: str) -> tuple[str, str, str]:
        parsed = urlparse(url)
        allowed_schemes = {"https"}
        if os.getenv("WATON_MEDIA_ALLOW_HTTP", "0").strip() == "1":
            allowed_schemes.add("http")
        if parsed.scheme.lower() not in allowed_schemes:
            raise ValueError("Unsupported media URL scheme.")

        host = parsed.hostname
        if not host:
            raise ValueError("Media URL host is missing.")

        resolved_ips: set[str] = set()
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            raise ValueError("Media URL host resolution failed.") from exc
        for info in infos:
            addr = info[4][0]
            if isinstance(addr, str):
                resolved_ips.add(addr)

        if not resolved_ips:
            raise ValueError("Media URL host resolution produced no address.")

        selected_ip = sorted(resolved_ips)[0]
        for raw_ip in resolved_ips:
            ip_obj = ipaddress.ip_address(raw_ip)
            if (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            ):
                raise ValueError("Media URL host resolves to a blocked network range.")

        return parsed.scheme.lower(), host, selected_ip

    async def encrypt_and_upload(self, media_type: str, raw_media: bytes) -> dict[str, str | bytes | int]:
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
        _, host, resolved_ip = self._validated_endpoint(url)
        transport = self._force_ip_connect_transport(host=host, resolved_ip=resolved_ip)
        try:
            async with httpx.AsyncClient(transport=transport) as strict_http:
                res = await strict_http.get(url)
                res.raise_for_status()
                encrypted_data = res.content
        finally:
            await transport.aclose()

        info = f"WhatsApp {media_type.capitalize()} Keys".encode()
        derived = hkdf(media_key, 112, bytes(32), info)

        iv = derived[:16]
        cipher_key = derived[16:48]

        actual_ciphertext = encrypted_data[:-10]
        return aes_cbc_decrypt(actual_ciphertext, cipher_key, iv)


def upload_with_retry(data: bytes, max_attempts: int = 3) -> dict[str, str | int | bool]:
    for attempt in range(1, max_attempts + 1):
        url = upload_once(data)
        if verify_remote_checksum(url, data):
            return {"url": url, "attempts": attempt, "verified": True}
    raise RuntimeError("upload failed after retries")
