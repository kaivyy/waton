"""Unit tests for Phase 4 parity features:
- Message Secret Framework (EncReaction, EncComment, Bot Message)
- Contact & Business QR links in ChatsAPI
- Link preview generator
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waton.client.chats import ChatsAPI
from waton.client.client import WAClient
from waton.protocol.binary_node import BinaryNode
from waton.utils.link_preview import get_url_info
from waton.utils.msg_secret import (
    apply_bot_message_hkdf,
    decrypt_comment,
    decrypt_reaction,
    encrypt_comment,
    encrypt_reaction,
    generate_msg_secret_key,
)


@pytest.fixture
def mock_client() -> MagicMock:
    client = MagicMock(spec=WAClient)
    client.generate_message_tag.return_value = "tag-call-qr"
    client.query = AsyncMock()
    client.send_node = AsyncMock()
    client.is_connected = True
    return client


# --- 1. Message Secret Framework Tests ---
def test_bot_message_hkdf() -> None:
    secret = os.urandom(32)
    derived = apply_bot_message_hkdf(secret)
    assert len(derived) == 32
    assert derived != secret


def test_comment_encryption_decryption() -> None:
    message_secret = os.urandom(32)
    plaintext = b"This is a comment on the announcement"

    enc_res = encrypt_comment(
        comment_payload=plaintext,
        root_message_id="ROOT-MSG-1",
        root_sender_jid="admin@s.whatsapp.net",
        root_chat_jid="community@g.us",
        own_jid="user@s.whatsapp.net",
        message_secret=message_secret,
    )

    assert "enc_comment_bytes" in enc_res
    assert len(enc_res["iv"]) == 12

    decrypted = decrypt_comment(
        ciphertext=enc_res["ciphertext"],
        iv=enc_res["iv"],
        root_message_id="ROOT-MSG-1",
        root_sender_jid="admin@s.whatsapp.net",
        comment_sender_jid="user@s.whatsapp.net",
        message_secret=message_secret,
    )

    assert decrypted == plaintext


def test_reaction_encryption_decryption() -> None:
    message_secret = os.urandom(32)
    plaintext = b"\x0a\x02\xf0\x9f\x91\x8d"  # protobuf for reaction thumbs up

    enc_res = encrypt_reaction(
        reaction_payload=plaintext,
        target_message_id="TARGET-MSG-2",
        target_sender_jid="poster@s.whatsapp.net",
        target_chat_jid="cag@g.us",
        own_jid="reactor@s.whatsapp.net",
        message_secret=message_secret,
    )

    assert "enc_reaction_bytes" in enc_res
    assert len(enc_res["iv"]) == 12

    decrypted = decrypt_reaction(
        ciphertext=enc_res["ciphertext"],
        iv=enc_res["iv"],
        target_message_id="TARGET-MSG-2",
        target_sender_jid="poster@s.whatsapp.net",
        reactor_jid="reactor@s.whatsapp.net",
        message_secret=message_secret,
    )

    assert decrypted == plaintext


# --- 2. Contact & Business QR Link Tests ---
@pytest.mark.asyncio
async def test_resolve_contact_qr_link(mock_client: MagicMock) -> None:
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="qr",
                attrs={"jid": "62811111111@s.whatsapp.net", "notify": "Alice", "type": "contact"},
            )
        ],
    )

    chats = ChatsAPI(mock_client)
    res = await chats.resolve_contact_qr_link("https://wa.me/qr/ABC123XYZ")
    assert res is not None
    assert res["jid"] == "62811111111@s.whatsapp.net"
    assert res["notify"] == "Alice"


@pytest.mark.asyncio
async def test_get_contact_qr_link(mock_client: MagicMock) -> None:
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[BinaryNode(tag="qr", attrs={"code": "MY_QR_CODE_123"})],
    )

    chats = ChatsAPI(mock_client)
    code = await chats.get_contact_qr_link(revoke=True)
    assert code == "MY_QR_CODE_123"


@pytest.mark.asyncio
async def test_resolve_business_message_link(mock_client: MagicMock) -> None:
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="qr",
                attrs={"jid": "62822222222@s.whatsapp.net", "notify": "Acme Store"},
                content=[
                    BinaryNode(tag="message", attrs={}, content=b"Hello I want to buy shoes"),
                    BinaryNode(tag="business", attrs={"verified_name": "Acme Official"}),
                ],
            )
        ],
    )

    chats = ChatsAPI(mock_client)
    res = await chats.resolve_business_message_link("https://wa.me/message/BIZ123")
    assert res is not None
    assert res["jid"] == "62822222222@s.whatsapp.net"
    assert res["message"] == "Hello I want to buy shoes"
    assert res["verified_name"] == "Acme Official"


# --- 3. Link Preview Generator Tests ---
@pytest.mark.asyncio
async def test_link_preview_no_url() -> None:
    res = await get_url_info("Hello there without any link")
    assert res is None


@pytest.mark.asyncio
async def test_link_preview_with_mock_html() -> None:
    mock_html = """
    <html>
      <head>
        <title>Waton Documentation</title>
        <meta property="og:description" content="WhatsApp Multi-Device Python Library" />
      </head>
      <body></body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = mock_html
    mock_resp.url = "https://example.com/docs"

    with patch("httpx.AsyncClient.get", AsyncMock(return_value=mock_resp)):
        info = await get_url_info("Check out https://example.com/docs for info")
        assert info is not None
        assert info["title"] == "Waton Documentation"
        assert info["description"] == "WhatsApp Multi-Device Python Library"
        assert info["matched-text"] == "https://example.com/docs"
