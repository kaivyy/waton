import asyncio
import base64
import os
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from waton.client.chats import ChatsAPI
from waton.client.groups import GroupsAPI
from waton.client.messages import MessagesAPI
from waton.client.newsletter import NewsletterAPI
from waton.client.presence import PresenceAPI
from waton.protocol.app_state import chat_modification_to_app_patch, process_contact_action
from waton.protocol.binary_node import BinaryNode
from waton.utils.crypto import aes_encrypt
from waton.utils.process_message import process_incoming_message
from waton.utils.protocol_message import _derive_message_addon_key
from waton.utils.tc_token import (
    TC_TOKEN_BUCKET_DURATION,
    TCTokenManager,
    build_tc_token_node,
    extract_tc_tokens,
    is_tc_token_expired,
    should_send_new_tc_token,
)


def test_tc_token_lifecycle():
    now = int(time.time())
    # Current token
    assert not is_tc_token_expired(now)
    # Expired token (> 28 days ago)
    old_ts = now - (TC_TOKEN_BUCKET_DURATION * 5)
    assert is_tc_token_expired(old_ts)
    assert is_tc_token_expired(None)
    assert is_tc_token_expired("invalid")

    # should_send_new_tc_token
    assert should_send_new_tc_token(None)
    assert should_send_new_tc_token(now - (TC_TOKEN_BUCKET_DURATION * 2))
    assert not should_send_new_tc_token(now)


def test_tc_token_manager_and_parsing():
    mgr = TCTokenManager()
    user_jid = "6281234567@s.whatsapp.net"
    token_bytes = b"sample_tc_token_123"
    now = int(time.time())

    mgr.save_token(user_jid, token_bytes, now)
    retrieved = mgr.get_token(user_jid)
    assert retrieved is not None
    assert retrieved["token"] == token_bytes

    # Should not issue right away since sender ts is fresh
    mgr.record_sender_timestamp(user_jid, now)
    assert not mgr.should_issue_to(user_jid)

    # Parsing from tokens binary node
    node = BinaryNode(
        tag="iq",
        attrs={"from": "s.whatsapp.net", "type": "result"},
        content=[
            BinaryNode(
                tag="tokens",
                attrs={},
                content=[
                    BinaryNode(
                        tag="token",
                        attrs={"type": "trusted_contact", "jid": user_jid, "t": str(now)},
                        content=token_bytes,
                    )
                ],
            )
        ],
    )
    parsed = extract_tc_tokens(node)
    assert len(parsed) == 1
    assert parsed[0]["jid"] == user_jid
    assert parsed[0]["token"] == token_bytes
    assert parsed[0]["timestamp"] == now


@pytest.mark.asyncio
async def test_presence_subscribe_attaches_tc_token():
    client = MagicMock()
    client.tc_token_manager = TCTokenManager()
    client.send_node = AsyncMock()

    user_jid = "628999@s.whatsapp.net"
    token_bytes = b"secret_tc_token"
    client.tc_token_manager.save_token(user_jid, token_bytes, int(time.time()))

    presence = PresenceAPI(client)
    await presence.presence_subscribe(user_jid)

    client.send_node.assert_called_once()
    sent_node = client.send_node.call_args[0][0]
    assert sent_node.tag == "presence"
    assert sent_node.attrs["to"] == user_jid
    assert sent_node.attrs["type"] == "subscribe"
    assert isinstance(sent_node.content, list)
    assert sent_node.content[0].tag == "tctoken"
    assert sent_node.content[0].content == token_bytes


def test_app_state_chat_modification_patches():
    # Mute
    mute_patch = chat_modification_to_app_patch({"mute": True}, "123@s.whatsapp.net")
    assert mute_patch["type"] == "regular_high"
    assert mute_patch["index"] == ["mute", "123@s.whatsapp.net"]
    assert mute_patch["syncAction"]["muteAction"]["muted"] is True

    # Archive
    archive_patch = chat_modification_to_app_patch({"archive": True}, "123@s.whatsapp.net")
    assert archive_patch["type"] == "regular_low"
    assert archive_patch["index"] == ["archive", "123@s.whatsapp.net"]

    # Pin
    pin_patch = chat_modification_to_app_patch({"pin": True}, "123@s.whatsapp.net")
    assert pin_patch["type"] == "regular_low"
    assert pin_patch["index"] == ["pin_v1", "123@s.whatsapp.net"]

    # Star
    star_patch = chat_modification_to_app_patch(
        {"star": True, "message_id": "MSG_1", "from_me": True}, "123@s.whatsapp.net"
    )
    assert star_patch["index"] == ["star", "123@s.whatsapp.net", "MSG_1", "1", "0"]

    # Mark read
    read_patch = chat_modification_to_app_patch({"mark_read": True}, "123@s.whatsapp.net")
    assert read_patch["index"] == ["markChatAsRead", "123@s.whatsapp.net"]

    # Contact action processing
    events = process_contact_action(
        {"fullName": "Alice Bob", "username": "alice", "lidJid": "999@lid"},
        id_="628111@s.whatsapp.net",
    )
    assert len(events) == 2
    assert events[0]["event"] == "contacts.upsert"
    assert events[0]["data"][0]["name"] == "Alice Bob"
    assert events[1]["event"] == "lid-mapping.update"
    assert events[1]["data"]["lid"] == "999@lid"


@pytest.mark.asyncio
async def test_message_secret_cache_and_enc_reaction_decryption():
    client = MagicMock()
    client.creds = None
    client.message_secrets = {}
    client.get_message_secret = lambda mid: client.message_secrets.get(mid)
    client.set_message_secret = lambda mid, sec: client.message_secrets.update({mid: sec})

    target_mid = "TARGET_MSG_123"
    message_secret = b"\x07" * 32
    client.set_message_secret(target_mid, message_secret)

    # Construct encrypted reaction payload
    creator_jid = "user1@s.whatsapp.net"
    reactor_jid = "user2@s.whatsapp.net"
    addon_key = _derive_message_addon_key(
        addon_label="Enc Reaction",
        message_id=target_mid,
        creator_jid=creator_jid,
        actor_jid=reactor_jid,
        message_secret=message_secret,
    )
    iv = b"\x01" * 12
    # Reaction plaintext protobuf: tag 1 = key, tag 2 = text, tag 3 = grouping_key, tag 4 = sender_timestamp_ms
    reaction_inner = b"\x12\x04\xf0\x9f\x91\x8d"  # field 2: emoji thumbs up 👍
    enc_ciphertext = aes_encrypt(reaction_inner, addon_key, iv, b"")

    # Enc reaction proto inside raw message (field 56)
    from waton.protocol.protobuf.wire import encode_len_delimited, encode_string
    target_key_bytes = encode_string(1, creator_jid) + encode_string(3, target_mid)
    enc_reaction_bytes = (
        encode_len_delimited(1, target_key_bytes)
        + encode_len_delimited(2, enc_ciphertext)
        + encode_len_delimited(3, iv)
    )
    raw_bytes = encode_len_delimited(56, enc_reaction_bytes)

    node = BinaryNode(
        tag="message",
        attrs={"id": "REACTION_1", "from": creator_jid, "participant": reactor_jid},
        content=raw_bytes,
    )

    msg = await process_incoming_message(node, client)
    assert msg.reaction == "👍"
    assert msg.encrypted_reaction is not None
    assert msg.encrypted_reaction.get("decrypted") is True


@pytest.mark.asyncio
async def test_group_accept_invite_v4():
    client = MagicMock()
    client.query = AsyncMock(return_value=BinaryNode(tag="iq", attrs={"type": "result"}))

    groups = GroupsAPI(client)
    res = await groups.group_accept_invite_v4(
        group_jid="12345-67890@g.us",
        invite_code="CODE123",
        invite_expiration=1730000000,
        admin_jid="admin@s.whatsapp.net",
    )
    assert res.tag == "iq"
    client.query.assert_called_once()
    sent_iq = client.query.call_args[0][0]
    assert sent_iq.attrs["to"] == "12345-67890@g.us"
    assert sent_iq.attrs["xmlns"] == "w:g2"
    assert sent_iq.content[0].tag == "accept"
    assert sent_iq.content[0].attrs["code"] == "CODE123"
    assert sent_iq.content[0].attrs["admin"] == "admin@s.whatsapp.net"


@pytest.mark.asyncio
async def test_newsletter_admin_and_view_receipt():
    client = MagicMock()
    client.query = AsyncMock(return_value=BinaryNode(tag="iq", attrs={"type": "result"}))
    client.send_node = AsyncMock()

    newsletter = NewsletterAPI(client)
    channel_jid = "123456789@newsletter"

    # Picture update & remove
    await newsletter.newsletter_update_picture(channel_jid, b"jpeg_bytes")
    await newsletter.newsletter_remove_picture(channel_jid)

    # Delete & Demote & Change Owner
    await newsletter.newsletter_delete(channel_jid)
    await newsletter.newsletter_change_owner(channel_jid, "newowner@s.whatsapp.net")
    await newsletter.newsletter_demote(channel_jid, "user@s.whatsapp.net")

    # Mark viewed
    await newsletter.newsletter_mark_viewed(channel_jid, ["101", "102"])
    client.send_node.assert_called_once()
    receipt_node = client.send_node.call_args[0][0]
    assert receipt_node.tag == "receipt"
    assert receipt_node.attrs["type"] == "view"
    assert receipt_node.attrs["to"] == channel_jid
    assert len(receipt_node.content[0].content) == 2


@pytest.mark.asyncio
async def test_chats_status_and_business_profile():
    client = MagicMock()
    # Mock status result
    status_result = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[BinaryNode(tag="status", attrs={}, content="Busy coding")],
    )
    client.query = AsyncMock(return_value=status_result)

    chats = ChatsAPI(client)
    status_text = await chats.fetch_status("user@s.whatsapp.net")
    assert status_text == "Busy coding"

    # Mock business profile result
    biz_result = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="business_profile",
                attrs={},
                content=[
                    BinaryNode(
                        tag="profile",
                        attrs={"jid": "biz@s.whatsapp.net"},
                        content=[
                            BinaryNode(tag="description", attrs={}, content="Official Store"),
                            BinaryNode(tag="email", attrs={}, content="support@store.com"),
                        ],
                    )
                ],
            )
        ],
    )
    client.query = AsyncMock(return_value=biz_result)
    profile = await chats.get_business_profile("biz@s.whatsapp.net")
    assert profile is not None
    assert profile["description"] == "Official Store"
    assert profile["email"] == "support@store.com"


@pytest.mark.asyncio
async def test_issue_privacy_tokens():
    client = MagicMock()
    client.query = AsyncMock(return_value=BinaryNode(tag="iq", attrs={"type": "result"}))

    chats = ChatsAPI(client)
    res = await chats.issue_privacy_tokens(["628111@s.whatsapp.net", "628222:1@s.whatsapp.net"], timestamp=1700000000)
    assert res.tag == "iq"
    client.query.assert_called_once()
    node = client.query.call_args[0][0]
    assert node.tag == "iq"
    assert node.attrs["xmlns"] == "privacy"
    tokens_container = node.content[0]
    assert tokens_container.tag == "tokens"
    assert len(tokens_container.content) == 2
    assert tokens_container.content[0].attrs["t"] == "1700000000"


@pytest.mark.asyncio
async def test_send_status_update():
    client = MagicMock()
    client.creds = MagicMock()
    client.creds.me = {"id": "628000:0@s.whatsapp.net"}
    client.storage = MagicMock()
    client.send_node = AsyncMock()

    messages = MessagesAPI(client)
    messages._collect_target_devices = AsyncMock(return_value=["628111:0@s.whatsapp.net"])
    messages._assert_sessions = AsyncMock()

    # Mock signal repository encrypt_message
    from unittest.mock import patch
    with patch("waton.client.messages.SignalRepository") as mock_repo_cls:
        mock_repo = MagicMock()
        mock_repo.encrypt_message = AsyncMock(return_value=("msg", b"enc_cipher"))
        mock_repo_cls.return_value = mock_repo

        msg_id = await messages.send_status_update(
            text="Hello status!",
            recipients=["628111@s.whatsapp.net"],
        )
        assert isinstance(msg_id, str)
        client.send_node.assert_called_once()
        sent_node = client.send_node.call_args[0][0]
        assert sent_node.tag == "message"
        assert sent_node.attrs["to"] == "status@broadcast"

