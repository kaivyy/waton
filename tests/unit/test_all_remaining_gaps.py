"""Unit tests for the 21 remaining protocol gap closures across all domains."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from waton.client.chats import ChatsAPI
from waton.client.client import WAClient
from waton.client.groups import GroupsAPI
from waton.client.media_upload import MediaUploadManager
from waton.client.messages import MessagesAPI
from waton.client.mex import MexClient
from waton.client.newsletter import NewsletterAPI
from waton.protocol.binary_node import BinaryNode
from waton.utils.auth import init_auth_creds
from waton.utils.chat_utils import (
    decode_syncd_snapshot,
    download_external_blob,
    extract_syncd_patches,
    is_group_chat,
    is_private_chat,
    normalize_chat_jid,
)


@pytest.fixture
def mock_client() -> MagicMock:
    client = MagicMock(spec=WAClient)
    client.creds = init_auth_creds()
    client.creds.me = {"id": "1234567890:1@s.whatsapp.net"}
    client.storage = MagicMock()
    client.generate_message_tag.return_value = "tag-gap-test"
    client.query = AsyncMock()
    client.send_node = AsyncMock()
    client.is_connected = True
    client.mex = MagicMock(spec=MexClient)
    client.mex.execute_wmex_query = AsyncMock()
    return client


# --- 1. Message Protocol Stanza Attributes (M1-M4) Tests ---
@pytest.mark.asyncio
async def test_pin_message_sends_edit_2(mock_client: MagicMock) -> None:
    messages_api = MessagesAPI(mock_client)
    # mock _assert_sessions and _collect_target_devices
    messages_api._assert_sessions = AsyncMock()
    messages_api._collect_target_devices = AsyncMock(return_value=["1234567890:1@s.whatsapp.net"])
    
    with MagicMock() as mock_repo:
        mock_repo.encrypt_message = AsyncMock(return_value=("msg", b"enc_payload"))
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("waton.client.messages.SignalRepository", lambda c, s: mock_repo)
            msg_id = await messages_api.pin_message(
                to_jid="9876543210@s.whatsapp.net",
                target_message_id="TARGET-PIN-123",
                duration_seconds=86400,
            )
            assert isinstance(msg_id, str)
            mock_client.send_node.assert_called_once()
            sent_node: BinaryNode = mock_client.send_node.call_args[0][0]
            assert sent_node.tag == "message"
            assert sent_node.attrs.get("edit") == "2"


@pytest.mark.asyncio
async def test_send_edit_sends_edit_1(mock_client: MagicMock) -> None:
    messages_api = MessagesAPI(mock_client)
    messages_api._assert_sessions = AsyncMock()
    messages_api._collect_target_devices = AsyncMock(return_value=["1234567890:1@s.whatsapp.net"])

    with MagicMock() as mock_repo:
        mock_repo.encrypt_message = AsyncMock(return_value=("msg", b"enc_payload"))
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("waton.client.messages.SignalRepository", lambda c, s: mock_repo)
            await messages_api.send_edit(
                to_jid="9876543210@s.whatsapp.net",
                target_message_id="TARGET-EDIT-123",
                text="Edited message content",
            )
            sent_node: BinaryNode = mock_client.send_node.call_args[0][0]
            assert sent_node.attrs.get("edit") == "1"


@pytest.mark.asyncio
async def test_send_delete_edit_7_and_8(mock_client: MagicMock) -> None:
    messages_api = MessagesAPI(mock_client)
    messages_api._assert_sessions = AsyncMock()
    messages_api._collect_target_devices = AsyncMock(return_value=["1234567890:1@s.whatsapp.net"])

    with MagicMock() as mock_repo:
        mock_repo.encrypt_message = AsyncMock(return_value=("msg", b"enc_payload"))
        mock_repo.encrypt_group_message = AsyncMock(return_value=(b"enc_group_payload", None))
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("waton.client.messages.SignalRepository", lambda c, s: mock_repo)
            
            # 1. Self revoke (edit="7")
            await messages_api.send_delete(
                to_jid="9876543210@s.whatsapp.net",
                target_message_id="TARGET-REVOKE-1",
                from_me=True,
            )
            sent_node1: BinaryNode = mock_client.send_node.call_args[0][0]
            assert sent_node1.attrs.get("edit") == "7"

            mock_client.send_node.reset_mock()

            # 2. Group Admin revoke (edit="8")
            await messages_api.send_delete(
                to_jid="123456789-group@g.us",
                target_message_id="TARGET-REVOKE-2",
                participant="author@s.whatsapp.net",
                from_me=False,
            )
            sent_node2: BinaryNode = mock_client.send_node.call_args[0][0]
            assert sent_node2.attrs.get("edit") == "8"


@pytest.mark.asyncio
async def test_send_poll_creation_includes_meta_node(mock_client: MagicMock) -> None:
    messages_api = MessagesAPI(mock_client)
    messages_api._assert_sessions = AsyncMock()
    messages_api._collect_target_devices = AsyncMock(return_value=["1234567890:1@s.whatsapp.net"])

    with MagicMock() as mock_repo:
        mock_repo.encrypt_message = AsyncMock(return_value=("msg", b"enc_payload"))
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("waton.client.messages.SignalRepository", lambda c, s: mock_repo)
            await messages_api.send_poll_creation(
                to_jid="9876543210@s.whatsapp.net",
                name="Best framework?",
                options=["Baileys", "whatsmeow", "waton"],
            )
            sent_node: BinaryNode = mock_client.send_node.call_args[0][0]
            assert isinstance(sent_node.content, list)
            meta_nodes = [c for c in sent_node.content if isinstance(c, BinaryNode) and c.tag == "meta"]
            assert len(meta_nodes) == 1
            assert meta_nodes[0].attrs.get("polltype") == "creation"


@pytest.mark.asyncio
async def test_send_ptv_method(mock_client: MagicMock) -> None:
    messages_api = MessagesAPI(mock_client)
    messages_api.send_video = AsyncMock(return_value="PTV_MSG_ID")
    res = await messages_api.send_ptv("123@s.whatsapp.net", b"fake_video_bytes", seconds=10)
    assert res == "PTV_MSG_ID"
    messages_api.send_video.assert_called_once_with(
        to_jid="123@s.whatsapp.net",
        video_bytes=b"fake_video_bytes",
        mimetype="video/mp4",
        caption="",
        seconds=10,
        height=0,
        width=0,
        ptv=True,
    )


# --- 2. ChatsAPI Syncd & Contact Gaps (C1-C6) Tests ---
@pytest.mark.asyncio
async def test_chats_api_contact_and_quick_reply(mock_client: MagicMock) -> None:
    chats = ChatsAPI(mock_client)
    chats.app_patch = AsyncMock()

    # Contact add/remove
    await chats.add_or_edit_contact("628123@s.whatsapp.net", {"fullName": "Test User"})
    chats.app_patch.assert_called_once()
    patch1 = chats.app_patch.call_args[0][0]
    assert patch1["type"] == "critical_unblock_low"
    assert patch1["operation"] == "set"

    chats.app_patch.reset_mock()
    await chats.remove_contact("628123@s.whatsapp.net")
    patch2 = chats.app_patch.call_args[0][0]
    assert patch2["operation"] == "remove"

    # Quick reply add/remove
    chats.app_patch.reset_mock()
    await chats.add_or_edit_quick_reply({"shortcut": "/hello", "message": "Hello world!"})
    patch3 = chats.app_patch.call_args[0][0]
    assert patch3["type"] == "regular"
    assert patch3["operation"] == "set"

    chats.app_patch.reset_mock()
    await chats.remove_quick_reply("123456789")
    patch4 = chats.app_patch.call_args[0][0]
    assert patch4["syncAction"]["quickReplyAction"]["deleted"] is True


@pytest.mark.asyncio
async def test_chats_api_dirty_bits_and_props_and_bot_list(mock_client: MagicMock) -> None:
    chats = ChatsAPI(mock_client)

    # Clean dirty bits
    await chats.clean_dirty_bits("account_sync", 1700000000)
    mock_client.send_node.assert_called_once()
    dirty_node = mock_client.send_node.call_args[0][0]
    assert dirty_node.attrs.get("xmlns") == "urn:xmpp:whatsapp:dirty"

    # Fetch props
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="props",
                attrs={},
                content=[BinaryNode(tag="prop", attrs={"config_code": "web_ab_flag", "config_value": "1"})],
            )
        ],
    )
    props = await chats.fetch_props()
    assert props.get("web_ab_flag") == "1"

    # Get bot list v2
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="bot",
                attrs={"v": "2"},
                content=[BinaryNode(tag="bot_profile", attrs={"jid": "13135550002@s.whatsapp.net", "name": "Meta AI"})],
            )
        ],
    )
    bots = await chats.get_bot_list_v2()
    assert len(bots) == 1
    assert bots[0]["name"] == "Meta AI"


# --- 3. Newsletter API Gaps (N1-N6) Tests ---
@pytest.mark.asyncio
async def test_newsletter_api_enhancements(mock_client: MagicMock) -> None:
    nl = NewsletterAPI(mock_client)

    # unmute
    nl.mute_newsletter = AsyncMock()
    await nl.unmute_newsletter("123456@newsletter")
    nl.mute_newsletter.assert_called_once_with("123456@newsletter", mute=False)

    # subscribers & admin count via MEX
    mock_client.mex.execute_wmex_query.side_effect = [
        [{"id": "sub1@s.whatsapp.net"}],
        {"admin_count": "5"},
    ]
    subs = await nl.newsletter_subscribers("123456@newsletter")
    assert len(subs) == 1
    admins = await nl.newsletter_admin_count("123456@newsletter")
    assert admins == 5

    # get_subscribed_newsletters
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="subscribed",
                attrs={},
                content=[
                    BinaryNode(tag="newsletter", attrs={"jid": "chan1@newsletter"}),
                    BinaryNode(tag="newsletter", attrs={"jid": "chan2@newsletter"}),
                ],
            )
        ],
    )
    channels = await nl.get_subscribed_newsletters()
    assert len(channels) == 2
    assert channels[0]["jid"] == "chan1@newsletter"

    # get_newsletter_info_with_invite
    mock_client.query.return_value = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[BinaryNode(tag="newsletter", attrs={"jid": "chan_invite@newsletter", "name": "Channel Inv"})],
    )
    info = await nl.get_newsletter_info_with_invite("https://whatsapp.com/channel/ABC123XYZ")
    assert info is not None
    assert info["name"] == "Channel Inv"

    # accept_tos_notice
    await nl.accept_tos_notice()
    sent = mock_client.send_node.call_args[0][0]
    assert sent.attrs.get("xmlns") == "tos"


# --- 4. Groups API Gaps (G1-G3) Tests ---
@pytest.mark.asyncio
async def test_groups_api_enhancements(mock_client: MagicMock) -> None:
    groups = GroupsAPI(mock_client)
    groups.group_invite_code = AsyncMock(return_value="INVITE_CODE_123")
    groups.group_accept_invite = AsyncMock(return_value="123456@g.us")

    link = await groups.get_group_invite_link("123456@g.us")
    assert link == "https://chat.whatsapp.com/INVITE_CODE_123"

    joined = await groups.join_group_with_link("https://chat.whatsapp.com/INVITE_CODE_123")
    assert joined == "123456@g.us"
    groups.group_accept_invite.assert_called_once_with("INVITE_CODE_123")


# --- 5. Media & Upload Gaps (U1) Tests ---
@pytest.mark.asyncio
async def test_upload_newsletter_unencrypted() -> None:
    upload_mgr = MediaUploadManager()
    upload_mgr.refresh_media_conn = AsyncMock(
        return_value=MagicMock(
            auth="sample_auth",
            hosts=[{"hostname": "mmg.whatsapp.net"}],
        )
    )

    with MagicMock() as mock_http:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "url": "https://mmg.whatsapp.net/newsletter/image/123",
            "direct_path": "/v/t62/123",
        }
        with pytest.MonkeyPatch.context() as mp:
            import httpx
            mock_client_inst = MagicMock()
            mock_client_inst.post = AsyncMock(return_value=mock_resp)
            mock_client_inst.__aenter__ = AsyncMock(return_value=mock_client_inst)
            mock_client_inst.__aexit__ = AsyncMock(return_value=None)
            mp.setattr(httpx, "AsyncClient", lambda **kwargs: mock_client_inst)

            res = await upload_mgr.upload_newsletter(
                client=MagicMock(),
                plaintext_bytes=b"sample_plaintext_image_content",
                media_type="image",
            )
            assert "direct_path" in res
            assert "file_sha256" in res


# --- 6. Chat Utils Syncd Snapshot Helpers (S1) Tests ---
def test_chat_utils_syncd_extract_and_decode() -> None:
    node = BinaryNode(
        tag="iq",
        attrs={"type": "result"},
        content=[
            BinaryNode(
                tag="sync",
                attrs={},
                content=[
                    BinaryNode(
                        tag="collection",
                        attrs={"name": "regular_low", "version": "12", "has_more_patches": "false"},
                        content=[
                            BinaryNode(tag="patches", attrs={}, content=[BinaryNode(tag="patch", attrs={}, content=b"patch1_bytes")]),
                            BinaryNode(tag="snapshot", attrs={}, content=b"\x08\x0c\x12\x04test"),
                        ],
                    )
                ],
            )
        ],
    )
    patches = extract_syncd_patches(node)
    assert "regular_low" in patches
    assert patches["regular_low"]["version"] == 12
    assert len(patches["regular_low"]["patches"]) == 1
    assert patches["regular_low"]["snapshot"] == b"\x08\x0c\x12\x04test"

    decoded_snap = decode_syncd_snapshot(b"\x08\x0c\x12\x04test")
    assert decoded_snap["version"] == 12
    assert len(decoded_snap["records"]) == 1
    assert decoded_snap["records"][0] == b"test"
