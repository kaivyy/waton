from __future__ import annotations

import base64
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waton.client.media_upload import (
    MEDIA_PATH_MAP,
    MediaConnInfo,
    MediaUploadManager,
    encode_base64_for_upload,
)
from waton.protocol.binary_node import BinaryNode


def test_encode_base64_for_upload_matches_baileys_spec() -> None:
    raw_hash = b"\xfa\xce\xde\xad" * 8
    result = encode_base64_for_upload(raw_hash)
    assert "+" not in result
    assert "/" not in result
    assert "=" not in result


@pytest.mark.asyncio
async def test_refresh_media_conn_queries_iq_stanza() -> None:
    manager = MediaUploadManager()

    mock_client = AsyncMock()
    # Mock IQ response node from WhatsApp server
    mock_response = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="media_conn",
                attrs={"auth": "test_auth_token", "ttl": "3600"},
                content=[
                    BinaryNode(
                        tag="host",
                        attrs={"hostname": "mmg.whatsapp.net", "maxContentLengthBytes": "104857600"},
                    )
                ],
            )
        ],
    )
    mock_client.query.return_value = mock_response

    conn_info = await manager.refresh_media_conn(mock_client)
    assert conn_info.auth == "test_auth_token"
    assert conn_info.ttl == 3600
    assert len(conn_info.hosts) == 1
    assert conn_info.hosts[0]["hostname"] == "mmg.whatsapp.net"

    # Second call should use cached info without re-querying
    conn_info_cached = await manager.refresh_media_conn(mock_client)
    assert conn_info_cached.auth == "test_auth_token"
    assert mock_client.query.call_count == 1


@pytest.mark.asyncio
async def test_upload_media_streams_post_to_mms_host() -> None:
    manager = MediaUploadManager()
    manager._cached_conn = MediaConnInfo(
        hosts=[{"hostname": "mmg.whatsapp.net", "maxContentLengthBytes": 100000}],
        auth="mock_auth",
        ttl=3600,
        fetch_date=time.time(),
    )

    mock_client = AsyncMock()
    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "url": "https://mmg.whatsapp.net/mms/image/ABCDEF",
        "direct_path": "/v/t62.7118-24/12345_n.enc",
    }

    with patch("httpx.AsyncClient.post", return_value=mock_http_response) as mock_post:
        result = await manager.upload_media(
            client=mock_client,
            final_encrypted=b"encrypted_media_bytes",
            media_type="image",
            file_enc_sha256=b"\x01" * 32,
        )

        assert result["url"] == "https://mmg.whatsapp.net/mms/image/ABCDEF"
        assert result["direct_path"] == "/v/t62.7118-24/12345_n.enc"
        assert mock_post.called
