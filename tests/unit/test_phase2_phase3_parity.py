"""Unit tests for Phase 2 and Phase 3 parity features:
- OnWhatsApp lookup
- MEX GraphQL client
- CSTokenManager & Reporting Tokens
- Streaming Media Encryption & Thumbnails
- BusinessAPI
- BroadcastAPI
- Identity Change Handler
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest

from waton.client.broadcast import BroadcastAPI
from waton.client.business import BusinessAPI
from waton.client.client import WAClient
from waton.client.identity_change_handler import IdentityChangeContext, handle_identity_change_node
from waton.client.media_stream import encrypt_file_to_temp, extract_image_thumb
from waton.client.mex import MexClient, MexError, QueryIds
from waton.client.usync import USyncQuery
from waton.protocol.binary_node import BinaryNode
from waton.utils.cs_token import CSTokenManager
from waton.utils.reporting_token import get_message_reporting_token, should_include_reporting_token


@pytest.fixture
def mock_client() -> MagicMock:
    client = MagicMock(spec=WAClient)
    client.generate_message_tag.return_value = "tag-999"
    client.query = AsyncMock()
    client.send_node = AsyncMock()
    client.is_connected = True
    client.creds = MagicMock()
    client.creds.me = {"id": "1234567890:0@s.whatsapp.net", "lid": "999888777@lid"}
    return client


# --- 1. OnWhatsApp Tests ---
@pytest.mark.asyncio
async def test_on_whatsapp_query(mock_client: MagicMock) -> None:
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="usync",
                attrs={},
                content=[
                    BinaryNode(
                        tag="list",
                        attrs={},
                        content=[
                            BinaryNode(
                                tag="user",
                                attrs={"jid": "62812345678@s.whatsapp.net"},
                                content=[BinaryNode(tag="contact", attrs={"type": "in"})],
                            ),
                            BinaryNode(
                                tag="user",
                                attrs={"jid": "62899999999@s.whatsapp.net"},
                                content=[BinaryNode(tag="contact", attrs={"type": "out"})],
                            ),
                        ],
                    )
                ],
            )
        ],
    )

    usync = USyncQuery(mock_client)
    res = await usync.on_whatsapp("+62 812-345-678", "62899999999")
    assert len(res) == 2
    assert res[0]["exists"] is True
    assert res[0]["jid"] == "62812345678@s.whatsapp.net"
    assert res[1]["exists"] is False


# --- 2. MEX GraphQL Tests ---
@pytest.mark.asyncio
async def test_mex_client_success(mock_client: MagicMock) -> None:
    response_payload = {
        "data": {
            "xwa2_newsletter": {
                "id": "12345@newsletter",
                "subscribers": 42,
            }
        }
    }
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="result",
                attrs={},
                content=json.dumps(response_payload).encode("utf-8"),
            )
        ],
    )

    mex = MexClient(mock_client)
    data = await mex.execute_wmex_query(QueryIds.METADATA, {"key": "value"}, data_path="xwa2_newsletter")
    assert isinstance(data, dict)
    assert data.get("id") == "12345@newsletter"
    assert data.get("subscribers") == 42


@pytest.mark.asyncio
async def test_mex_client_error(mock_client: MagicMock) -> None:
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="result",
                attrs={},
                content=json.dumps({"errors": [{"message": "Rate limit exceeded", "extensions": {"error_code": 429}}]}).encode("utf-8"),
            )
        ],
    )

    mex = MexClient(mock_client)
    with pytest.raises(MexError) as exc_info:
        await mex.execute_wmex_query(QueryIds.SUBSCRIBERS, {})
    assert "Rate limit exceeded" in str(exc_info.value)
    assert exc_info.value.status_code == 429


# --- 3. CSToken & Reporting Token Tests ---
def test_cs_token_manager() -> None:
    csm = CSTokenManager()
    assert csm.generate_cs_token("12345@lid") is None

    salt = os.urandom(32)
    csm.set_nct_salt(salt)
    assert csm.get_nct_salt() == salt

    token = csm.generate_cs_token("12345@lid")
    assert token is not None
    assert len(token) == 32

    node = CSTokenManager.build_cs_token_node(token)
    assert node.tag == "cstoken"
    assert node.content == token


def test_reporting_token() -> None:
    msg_dict = {"conversation": "hello"}
    assert should_include_reporting_token(msg_dict) is True

    reaction_dict = {"reactionMessage": {"text": "❤️"}}
    assert should_include_reporting_token(reaction_dict) is False

    secret = os.urandom(32)
    node = get_message_reporting_token(
        message_secret=secret,
        message_bytes=b"\x0a\x05hello",
        sender_jid="123@s.whatsapp.net",
        remote_jid="456@s.whatsapp.net",
        message_id="msg-1",
    )
    assert node.tag == "reporting"
    assert isinstance(node.content, list)
    assert len(node.content) == 1
    assert node.content[0].tag == "reporting_token"
    assert node.content[0].attrs.get("v") == "2"


# --- 4. Streaming Media Crypto & Thumbnails ---
def test_streaming_media_encryption_and_thumb() -> None:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Test large binary payload " * 1000)
        temp_in = f.name

    try:
        enc_res = encrypt_file_to_temp(temp_in, media_type="document")
        assert "temp_file_path" in enc_res
        assert os.path.exists(enc_res["temp_file_path"])
        assert enc_res["file_length"] > 0
        assert len(enc_res["media_key"]) == 32
        os.remove(enc_res["temp_file_path"])
    finally:
        os.remove(temp_in)

    # Test thumbnail helper
    try:
        from PIL import Image
        import io
        img = Image.new("RGB", (100, 100), color="blue")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        raw_jpeg = buf.getvalue()

        thumb = extract_image_thumb(raw_jpeg, max_size=32)
        assert len(thumb) > 0
    except ImportError:
        pass


# --- 5. BusinessAPI Tests ---
@pytest.mark.asyncio
async def test_business_api(mock_client: MagicMock) -> None:
    mock_client.query.return_value = BinaryNode(tag="iq", attrs={"type": "result"}, content=[])
    biz = BusinessAPI(mock_client)

    catalog = await biz.get_catalog("biz@s.whatsapp.net", limit=5)
    assert mock_client.query.called
    assert "node" in catalog

    await biz.get_collections("biz@s.whatsapp.net", limit=3)
    assert mock_client.query.called

    await biz.get_order_details("order-123", "token-xyz")
    assert mock_client.query.called


# --- 6. BroadcastAPI Tests ---
@pytest.mark.asyncio
async def test_broadcast_api(mock_client: MagicMock) -> None:
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="privacy",
                attrs={},
                content=[
                    BinaryNode(
                        tag="list",
                        attrs={"type": "whitelist", "default": "true"},
                        content=[
                            BinaryNode(tag="user", attrs={"jid": "contact1@s.whatsapp.net"}),
                            BinaryNode(tag="user", attrs={"jid": "contact2@s.whatsapp.net"}),
                        ],
                    )
                ],
            )
        ],
    )
    bcast = BroadcastAPI(mock_client)
    privacy = await bcast.get_status_privacy()
    assert privacy["type"] == "whitelist"
    assert len(privacy["list"]) == 2

    recipients = await bcast.get_status_recipients()
    assert recipients == ["contact1@s.whatsapp.net", "contact2@s.whatsapp.net"]


# --- 7. Identity Change Handler Tests ---
@pytest.mark.asyncio
async def test_identity_change_handler() -> None:
    assert_mock = AsyncMock()
    ctx = IdentityChangeContext(
        me_id="self:0@s.whatsapp.net",
        validate_session=AsyncMock(return_value=True),
        assert_sessions=assert_mock,
        debounce_cache={},
    )

    node = BinaryNode(
        tag="notification",
        attrs={"from": "target@s.whatsapp.net", "type": "encrypt"},
        content=[BinaryNode(tag="identity", attrs={})],
    )

    res = await handle_identity_change_node(node, ctx)
    assert res["action"] == "session_refreshed"
    assert assert_mock.called
