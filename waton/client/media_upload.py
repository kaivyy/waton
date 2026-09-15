from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from waton.core.jid import S_WHATSAPP_NET
from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from waton.client.client import WAClient

MEDIA_PATH_MAP: dict[str, str] = {
    "image": "/mms/image",
    "video": "/mms/video",
    "document": "/mms/document",
    "audio": "/mms/audio",
    "sticker": "/mms/image",
    "thumbnail-link": "/mms/image",
    "product-catalog-image": "/product/image",
    "md-msg-hist": "/mms/md-app-state",
    "biz-cover-photo": "/pps/biz-cover-photo",
}

DEFAULT_ORIGIN = "https://web.whatsapp.com"


def encode_base64_for_upload(b64_or_bytes: bytes | str) -> str:
    if isinstance(b64_or_bytes, bytes):
        raw_b64 = base64.b64encode(b64_or_bytes).decode("ascii")
    else:
        raw_b64 = b64_or_bytes
    safe_str = raw_b64.replace("+", "-").replace("/", "_").rstrip("=")
    return quote(safe_str, safe="")


@dataclass
class MediaConnInfo:
    hosts: list[dict[str, Any]]
    auth: str
    ttl: int
    fetch_date: float


class MediaUploadManager:
    """Manages WhatsApp MMS media connection tokens and HTTP uploads."""

    def __init__(self) -> None:
        self._cached_conn: MediaConnInfo | None = None

    async def refresh_media_conn(self, client: WAClient, force: bool = False) -> MediaConnInfo:
        now = time.time()
        if (
            self._cached_conn is not None
            and not force
            and (now - self._cached_conn.fetch_date) < self._cached_conn.ttl
        ):
            return self._cached_conn

        iq_node = BinaryNode(
            tag="iq",
            attrs={
                "type": "set",
                "xmlns": "w:m",
                "to": S_WHATSAPP_NET,
            },
            content=[BinaryNode(tag="media_conn", attrs={})],
        )
        result = await client.query(iq_node)
        media_conn_node = self._get_child(result, "media_conn")
        if media_conn_node is None:
            raise RuntimeError("WhatsApp server returned empty media_conn node")

        hosts: list[dict[str, Any]] = []
        for child in self._get_children(media_conn_node, "host"):
            hostname = child.attrs.get("hostname")
            if hostname:
                max_len = int(child.attrs.get("maxContentLengthBytes", "0"))
                hosts.append({"hostname": hostname, "maxContentLengthBytes": max_len})

        auth = media_conn_node.attrs.get("auth", "")
        ttl = int(media_conn_node.attrs.get("ttl", "3600"))

        conn_info = MediaConnInfo(
            hosts=hosts,
            auth=auth,
            ttl=ttl,
            fetch_date=now,
        )
        self._cached_conn = conn_info
        return conn_info

    async def upload_media(
        self,
        client: WAClient,
        final_encrypted: bytes,
        media_type: str,
        file_enc_sha256: bytes,
        timeout: float = 60.0,
    ) -> dict[str, str]:
        conn_info = await self.refresh_media_conn(client)
        token = encode_base64_for_upload(file_enc_sha256)
        auth = quote(conn_info.auth, safe="")
        path = MEDIA_PATH_MAP.get(media_type, "/mms/image")

        headers = {
            "Content-Type": "application/octet-stream",
            "Origin": DEFAULT_ORIGIN,
        }

        last_error: Exception | None = None
        for host_info in conn_info.hosts:
            hostname = host_info["hostname"]
            upload_url = f"https://{hostname}{path}/{token}?auth={auth}&token={token}"
            try:
                async with httpx.AsyncClient(timeout=timeout) as http:
                    response = await http.post(
                        upload_url,
                        content=final_encrypted,
                        headers=headers,
                    )
                    if response.status_code in (200, 201):
                        raw_data = response.json()
                        data = (await raw_data) if hasattr(raw_data, "__await__") else raw_data
                        return {
                            "url": str(data.get("url", upload_url)),
                            "direct_path": str(data.get("direct_path", "")),
                        }
                    response.raise_for_status()
            except Exception as exc:
                last_error = exc
                continue

        if last_error is not None:
            raise last_error
        raise RuntimeError("failed to upload media to any WhatsApp MMS host")

    @staticmethod
    def _get_child(node: BinaryNode | None, tag: str) -> BinaryNode | None:
        if node is None or not isinstance(node.content, list):
            return None
        for child in node.content:
            if isinstance(child, BinaryNode) and child.tag == tag:
                return child
        return None

    @classmethod
    def _get_children(cls, node: BinaryNode | None, tag: str) -> list[BinaryNode]:
        if node is None or not isinstance(node.content, list):
            return []
        return [child for child in node.content if isinstance(child, BinaryNode) and child.tag == tag]
