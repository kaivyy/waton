from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

import httpx

from typing import Any

from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf.wire import iter_fields
from waton.utils.crypto import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_decrypt,
    aes_encrypt,
    generate_random_bytes,
    hkdf,
    hmac_sha256,
    sha256,
)
from waton.client.media_upload import MediaUploadManager
from waton.utils.media_utils import derive_media_keys, upload_once, verify_remote_checksum



class MediaManager:
    """Handles media encryption, upload and decryption helpers."""

    def __init__(self, client: Any | None = None) -> None:
        self.client = client
        self.http = httpx.AsyncClient()
        self.upload_manager = MediaUploadManager()


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

        keys = derive_media_keys(media_key, media_type)
        iv = keys["iv"]
        cipher_key = keys["cipher_key"]
        mac_key = keys["mac_key"]

        enc_media = aes_cbc_encrypt(raw_media, cipher_key, iv)
        mac = hmac_sha256(mac_key, iv + enc_media)[:10]
        final_encrypted = enc_media + mac

        file_hash = sha256(raw_media)
        enc_file_hash = sha256(final_encrypted)

        direct_path = ""
        if self.client is not None and hasattr(self.client, "query"):
            upload_result = await self.upload_manager.upload_media(
                self.client, final_encrypted, media_type, enc_file_hash
            )
            url = str(upload_result["url"])
            direct_path = upload_result.get("direct_path", "")
        else:
            upload_result = upload_with_retry(final_encrypted)
            url = str(upload_result["url"])

        meta: dict[str, str | bytes | int] = {
            "url": url,
            "mediaKey": media_key,
            "fileSha256": file_hash,
            "fileEncSha256": enc_file_hash,
            "fileLength": len(raw_media),
            "mediaType": media_type,
        }
        if direct_path:
            meta["directPath"] = direct_path
        return meta

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

        keys = derive_media_keys(media_key, media_type)
        iv = keys["iv"]
        cipher_key = keys["cipher_key"]

        actual_ciphertext = encrypted_data[:-10]
        return aes_cbc_decrypt(actual_ciphertext, cipher_key, iv)

    @staticmethod
    def encrypt_media_retry_receipt(message_id: str, media_key: bytes) -> tuple[bytes, bytes]:
        """Encrypts ServerErrorReceipt protobuf for requesting media re-upload from sender."""
        msg_bytes = message_id.encode("utf-8")
        plaintext = b"\n" + bytes([len(msg_bytes)]) + msg_bytes
        retry_key = hkdf(media_key, 32, salt=b"", info=b"WhatsApp Media Retry Notification")
        iv = generate_random_bytes(12)
        ciphertext = aes_encrypt(plaintext, retry_key, iv, aad=msg_bytes)
        return ciphertext, iv

    async def send_media_retry_receipt(
        self,
        *,
        message_id: str,
        chat_jid: str,
        media_key: bytes,
        is_from_me: bool = False,
        participant: str | None = None,
    ) -> None:
        """Sends server-error retry receipt to re-download expired WhatsApp media."""
        if self.client is None:
            raise ValueError("Client instance required to send media retry receipt")

        ciphertext, iv = self.encrypt_media_retry_receipt(message_id, media_key)
        rmr_attrs: dict[str, str] = {
            "jid": chat_jid,
            "from_me": "true" if is_from_me else "false",
        }
        if participant:
            rmr_attrs["participant"] = participant

        to_jid = "s.whatsapp.net"
        if hasattr(self.client, "creds") and self.client.creds and self.client.creds.me:
            to_jid = self.client.creds.me.get("id", "s.whatsapp.net")

        node = BinaryNode(
            tag="receipt",
            attrs={
                "id": message_id,
                "to": to_jid,
                "type": "server-error",
            },
            content=[
                BinaryNode(
                    tag="encrypt",
                    attrs={},
                    content=[
                        BinaryNode(tag="enc_p", attrs={}, content=ciphertext),
                        BinaryNode(tag="enc_iv", attrs={}, content=iv),
                    ],
                ),
                BinaryNode(tag="rmr", attrs=rmr_attrs),
            ],
        )
        await self.client.send_node(node)

    @staticmethod
    def decrypt_media_retry_notification(
        *,
        media_key: bytes,
        ciphertext: bytes,
        iv: bytes,
        message_id: str,
    ) -> dict[str, Any]:
        """Decrypts incoming mediaretry notification payload to get fresh direct_path."""
        retry_key = hkdf(media_key, 32, salt=b"", info=b"WhatsApp Media Retry Notification")
        plaintext = aes_decrypt(ciphertext, retry_key, iv, aad=message_id.encode("utf-8"))
        out: dict[str, Any] = {"message_id": message_id}
        for field_no, wire_type, value in iter_fields(plaintext):
            if field_no == 1 and wire_type == 2:
                out["stanza_id"] = bytes(value).decode("utf-8", errors="replace")
            elif field_no == 2 and wire_type == 2:
                out["direct_path"] = bytes(value).decode("utf-8", errors="replace")
            elif field_no == 3 and wire_type == 0:
                out["result"] = int(value)
        return out



def upload_with_retry(data: bytes, max_attempts: int = 3) -> dict[str, str | int | bool]:
    for attempt in range(1, max_attempts + 1):
        url = upload_once(data)
        if verify_remote_checksum(url, data):
            return {"url": url, "attempts": attempt, "verified": True}
    raise RuntimeError("upload failed after retries")
