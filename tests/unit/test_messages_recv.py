from __future__ import annotations

import base64

import pytest

from waton.client.messages_recv import (
    _unpad_random_max16,
    build_message_ack,
    build_retry_receipt_node,
    classify_incoming_node,
    decode_ack_node,
    decode_call_node,
    decode_incoming_message_node,
    decode_notification_node,
    decode_receipt_node,
    normalize_incoming_node,
)
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import WAProto_pb2 as wa_pb2
from waton.protocol.protobuf.wire import _encode_len_delimited, _encode_string, _encode_varint_field


def test_classify_message_node() -> None:
    node = BinaryNode(tag="message", attrs={"id": "1"}, content=[])
    assert classify_incoming_node(node) == "message"


def test_classify_call_node() -> None:
    node = BinaryNode(tag="call", attrs={"id": "c1"}, content=[])
    assert classify_incoming_node(node) == "call"


@pytest.mark.asyncio
async def test_decrypt_and_normalize_enc_message(monkeypatch: pytest.MonkeyPatch) -> None:
    del monkeypatch

    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            assert jid == "111@s.whatsapp.net"
            assert type_str == "msg"
            assert ciphertext == b"ciphertext"
            msg = wa_pb2.Message()
            msg.conversation = "hi"
            return msg.SerializeToString()

    enc_node = BinaryNode(
        tag="message",
        attrs={"from": "111@s.whatsapp.net", "id": "m-1", "t": "123"},
        content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"ciphertext")],
    )
    event = await decode_incoming_message_node(enc_node, FakeRepo())
    assert event["type"] == "messages.upsert"
    assert event["message"]["id"] == "m-1"
    assert event["message"]["from"] == "111@s.whatsapp.net"
    assert event["message"]["timestamp"] == 123
    assert event["message"]["text"] == "hi"


@pytest.mark.asyncio
async def test_decode_plain_device_sent_message_fallback() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    payload = wa_pb2.Message()
    payload.deviceSentMessage.destinationJid = "222@s.whatsapp.net"
    payload.deviceSentMessage.message.extendedTextMessage.text = "device mirror hello"

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-2", "from": "222@s.whatsapp.net"},
            content=payload.SerializeToString(),
        ),
        FakeRepo(),
    )
    assert event["message"]["text"] == "device mirror hello"


@pytest.mark.asyncio
async def test_decode_plain_reaction_message_event() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    payload = wa_pb2.Message()
    payload.reactionMessage.key.id = "msg-123"
    payload.reactionMessage.text = "👍"

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-react", "from": "222@s.whatsapp.net"},
            content=payload.SerializeToString(),
        ),
        FakeRepo(),
    )
    assert event["type"] == "messages.reaction"
    assert event["reaction"]["target_id"] == "msg-123"
    assert event["reaction"]["text"] == "👍"
    assert event["message"]["reaction"] == "👍"


@pytest.mark.asyncio
async def test_decode_plain_document_message_event() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    document_payload = (
        _encode_string(1, "https://cdn.example/doc.pdf")
        + _encode_string(2, "application/pdf")
        + _encode_string(8, "doc.pdf")
        + _encode_string(20, "invoice")
    )
    message_payload = _encode_len_delimited(7, document_payload)

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-doc", "from": "222@s.whatsapp.net"},
            content=message_payload,
        ),
        FakeRepo(),
    )
    assert event["type"] == "messages.upsert"
    assert event["message"]["content_type"] == "document"
    assert event["message"]["media_url"] == "https://cdn.example/doc.pdf"
    assert event["message"]["content"]["file_name"] == "doc.pdf"
    assert event["message"]["content"]["caption"] == "invoice"


@pytest.mark.asyncio
async def test_decode_protocol_revoke_message_event() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    protocol_key = _encode_string(3, "target-mid")
    protocol_payload = _encode_len_delimited(1, protocol_key) + _encode_varint_field(2, 0)
    message_payload = _encode_len_delimited(12, protocol_payload)

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-proto", "from": "222@s.whatsapp.net"},
            content=message_payload,
        ),
        FakeRepo(),
    )
    assert event["type"] == "messages.revoke"
    assert event["protocol"]["type_name"] == "REVOKE"
    assert event["protocol"]["target_message_id"] == "target-mid"


@pytest.mark.asyncio
async def test_decode_protocol_app_state_key_share_event() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    key_id_payload = _encode_len_delimited(1, b"key-1")
    key_data_payload = _encode_len_delimited(1, b"\x11" * 32)
    key_item_payload = _encode_len_delimited(1, key_id_payload) + _encode_len_delimited(2, key_data_payload)
    share_payload = _encode_len_delimited(1, key_item_payload)
    protocol_payload = _encode_varint_field(2, 6) + _encode_len_delimited(7, share_payload)
    message_payload = _encode_len_delimited(12, protocol_payload)

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-app-state", "from": "222@s.whatsapp.net"},
            content=message_payload,
        ),
        FakeRepo(),
    )
    assert event["type"] == "messages.app_state_sync_key_share"
    assert event["protocol"]["app_state_sync_key_share"]["count"] == 1
    assert (
        event["protocol"]["app_state_sync_key_share"]["keys"][0]["key_id_b64"]
        == base64.b64encode(b"key-1").decode("ascii")
    )


@pytest.mark.asyncio
async def test_decode_encrypted_reaction_event() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    key_payload = _encode_string(3, "target-mid")
    enc_reaction_payload = (
        _encode_len_delimited(1, key_payload)
        + _encode_len_delimited(2, b"enc-react")
        + _encode_len_delimited(3, b"iv-react")
    )
    message_payload = _encode_len_delimited(56, enc_reaction_payload)

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-enc-react", "from": "222@s.whatsapp.net"},
            content=message_payload,
        ),
        FakeRepo(),
    )
    assert event["type"] == "messages.reaction_encrypted"
    assert event["encrypted_reaction"]["target_message_id"] == "target-mid"
    assert event["message"]["encrypted_reaction"]["enc_payload_b64"] == base64.b64encode(b"enc-react").decode("ascii")


@pytest.mark.asyncio
async def test_decode_encrypted_event_response_event() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    key_payload = _encode_string(3, "event-mid")
    enc_event_payload = (
        _encode_len_delimited(1, key_payload)
        + _encode_len_delimited(2, b"enc-event")
        + _encode_len_delimited(3, b"iv-event")
    )
    message_payload = _encode_len_delimited(76, enc_event_payload)

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-enc-event", "from": "222@s.whatsapp.net"},
            content=message_payload,
        ),
        FakeRepo(),
    )
    assert event["type"] == "messages.event_response_encrypted"
    assert event["event_response"]["event_creation_message_id"] == "event-mid"
    assert event["message"]["event_response"]["enc_iv_b64"] == base64.b64encode(b"iv-event").decode("ascii")


@pytest.mark.asyncio
async def test_decode_encrypted_poll_update_event() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    key_payload = _encode_string(3, "poll-mid")
    vote_payload = _encode_len_delimited(1, b"enc-vote") + _encode_len_delimited(2, b"iv-vote")
    poll_update_payload = (
        _encode_len_delimited(1, key_payload)
        + _encode_len_delimited(2, vote_payload)
        + _encode_varint_field(4, 9999)
    )
    message_payload = _encode_len_delimited(50, poll_update_payload)

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-poll", "from": "222@s.whatsapp.net"},
            content=message_payload,
        ),
        FakeRepo(),
    )
    assert event["type"] == "messages.poll_update_encrypted"
    assert event["poll_update"]["poll_creation_message_id"] == "poll-mid"
    assert event["poll_update"]["sender_timestamp_ms"] == 9999
    assert event["message"]["poll_update"]["vote"]["enc_payload_b64"] == base64.b64encode(b"enc-vote").decode("ascii")


@pytest.mark.asyncio
async def test_decode_poll_creation_message_extracts_secret() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            raise AssertionError("decrypt_message must not be called for plaintext node")

    secret = bytes(range(32))
    context_info_payload = _encode_len_delimited(3, secret)
    poll_creation_payload = (
        _encode_len_delimited(1, b"enc-key")
        + _encode_string(2, "Lunch?")
        + _encode_len_delimited(5, context_info_payload)
    )
    message_payload = _encode_len_delimited(49, poll_creation_payload)

    event = await decode_incoming_message_node(
        BinaryNode(
            tag="message",
            attrs={"id": "m-poll-create", "from": "222@s.whatsapp.net"},
            content=message_payload,
        ),
        FakeRepo(),
    )
    assert event["type"] == "messages.upsert"
    assert event["message"]["content_type"] == "poll_creation"
    assert event["message"]["message_secret_b64"] == base64.b64encode(secret).decode("ascii")
    assert event["message"]["content"]["name"] == "Lunch?"


def test_decode_receipt_node_items() -> None:
    node = BinaryNode(
        tag="receipt",
        attrs={"id": "rid-root", "from": "333@s.whatsapp.net", "type": "read", "t": "77"},
        content=[
            BinaryNode(tag="item", attrs={"id": "rid-1"}),
            BinaryNode(tag="item", attrs={"id": "rid-2"}),
        ],
    )
    event = decode_receipt_node(node)
    assert event["type"] == "messages.receipt"
    assert event["receipt"]["from"] == "333@s.whatsapp.net"
    assert event["receipt"]["receipt_type"] == "read"
    assert event["receipt"]["message_ids"] == ["rid-1", "rid-2"]
    assert event["receipt"]["timestamp"] == 77


def test_decode_retry_receipt_node() -> None:
    node = BinaryNode(
        tag="receipt",
        attrs={
            "id": "rid-root",
            "from": "333@s.whatsapp.net",
            "participant": "333:1@s.whatsapp.net",
            "type": "retry",
            "t": "88",
        },
        content=[
            BinaryNode(tag="retry", attrs={"count": "2", "id": "rid-root", "t": "88", "v": "1"}),
            BinaryNode(tag="item", attrs={"id": "rid-1"}),
        ],
    )
    event = decode_receipt_node(node)
    assert event["type"] == "messages.retry_request"
    assert event["receipt"]["is_retry"] is True
    assert event["receipt"]["message_ids"] == ["rid-1"]
    assert event["receipt"]["retry"]["count"] == 2
    assert event["receipt"]["retry"]["id"] == "rid-root"
    assert event["receipt"]["retry"]["version"] == "1"


def test_decode_receipt_node_derives_status_fields() -> None:
    node = BinaryNode(
        tag="receipt",
        attrs={"id": "rid-read", "from": "333@s.whatsapp.net", "type": "read-self", "t": "90"},
        content=[BinaryNode(tag="item", attrs={"id": "rid-1"})],
    )
    event = decode_receipt_node(node)
    assert event["type"] == "messages.receipt"
    assert event["receipt"]["receipt_type"] == "read-self"
    assert event["receipt"]["status"] == "read"
    assert event["receipt"]["is_read"] is True
    assert event["receipt"]["is_played"] is False
    assert event["receipt"]["is_delivery"] is False


def test_decode_notification_node_kind_and_children() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "nid-1", "from": "s.whatsapp.net", "type": "encrypt"},
        content=[BinaryNode(tag="encrypt", attrs={}), BinaryNode(tag="count", attrs={}, content=b"1")],
    )
    event = decode_notification_node(node)
    assert event["type"] == "messages.notification"
    assert event["notification"]["kind"] == "encrypt"
    assert event["notification"]["children"] == ["encrypt", "count"]


def test_decode_notification_node_protocol_fields() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "nid-2", "from": "999@g.us", "type": "w:gp2"},
        content=[BinaryNode(tag="remove", attrs={"jid": "111@s.whatsapp.net"})],
    )
    event = decode_notification_node(node)
    protocol = event["notification"]["protocol"]
    assert protocol["namespace"] == "w:gp2"
    assert protocol["action"] == "remove"
    assert protocol["attrs"]["jid"] == "111@s.whatsapp.net"
    assert event["notification"]["group_event"]["kind"] == "participants"
    assert event["notification"]["group_event"]["action"] == "remove"
    assert event["notification"]["group_event"]["participants"] == ["111@s.whatsapp.net"]


def test_decode_group_notification_announcement_and_restrict_states() -> None:
    announcement = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={"id": "nid-g-1", "from": "999@g.us", "type": "w:gp2"},
            content=[BinaryNode(tag="announcement", attrs={})],
        )
    )
    assert announcement["notification"]["group_event"]["kind"] == "metadata"
    assert announcement["notification"]["group_event"]["action"] == "announce"
    assert announcement["notification"]["group_event"]["value"] == "on"

    unlocked = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={"id": "nid-g-2", "from": "999@g.us", "type": "w:gp2"},
            content=[BinaryNode(tag="unlocked", attrs={})],
        )
    )
    assert unlocked["notification"]["group_event"]["kind"] == "metadata"
    assert unlocked["notification"]["group_event"]["action"] == "restrict"
    assert unlocked["notification"]["group_event"]["value"] == "off"


def test_decode_group_notification_join_approval_mode_and_create() -> None:
    join_mode = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={"id": "nid-g-3", "from": "999@g.us", "type": "w:gp2"},
            content=[
                BinaryNode(
                    tag="membership_approval_mode",
                    attrs={},
                    content=[BinaryNode(tag="group_join", attrs={"state": "on"})],
                )
            ],
        )
    )
    assert join_mode["notification"]["group_event"]["kind"] == "metadata"
    assert join_mode["notification"]["group_event"]["action"] == "join_approval_mode"
    assert join_mode["notification"]["group_event"]["value"] == "on"

    create = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={"id": "nid-g-4", "from": "999@g.us", "type": "w:gp2"},
            content=[
                BinaryNode(
                    tag="create",
                    attrs={"subject": "New Group"},
                    content=[
                        BinaryNode(tag="participant", attrs={"jid": "111@s.whatsapp.net"}),
                        BinaryNode(tag="participant", attrs={"jid": "222@s.whatsapp.net"}),
                    ],
                )
            ],
        )
    )
    assert create["notification"]["group_event"]["kind"] == "create"
    assert create["notification"]["group_event"]["subject"] == "New Group"
    assert create["notification"]["group_event"]["participants"] == ["111@s.whatsapp.net", "222@s.whatsapp.net"]


def test_decode_group_notification_member_add_mode_and_not_ephemeral() -> None:
    add_mode = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={"id": "nid-g-5", "from": "999@g.us", "type": "w:gp2"},
            content=[BinaryNode(tag="member_add_mode", attrs={}, content=b"all_member_add")],
        )
    )
    assert add_mode["notification"]["group_event"]["kind"] == "metadata"
    assert add_mode["notification"]["group_event"]["action"] == "member_add_mode"
    assert add_mode["notification"]["group_event"]["value"] == "all_member_add"

    not_ephemeral = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={"id": "nid-g-6", "from": "999@g.us", "type": "w:gp2"},
            content=[BinaryNode(tag="not_ephemeral", attrs={})],
        )
    )
    assert not_ephemeral["notification"]["group_event"]["kind"] == "metadata"
    assert not_ephemeral["notification"]["group_event"]["action"] == "ephemeral"
    assert not_ephemeral["notification"]["group_event"]["value"] == "0"


def test_decode_group_notification_membership_requests_created_revoked_rejected() -> None:
    created = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={
                "id": "nid-g-7",
                "from": "999@g.us",
                "type": "w:gp2",
                "participant": "admin@s.whatsapp.net",
            },
            content=[
                BinaryNode(
                    tag="created_membership_requests",
                    attrs={"request_method": "invite_link"},
                    content=[BinaryNode(tag="participant", attrs={"jid": "user@s.whatsapp.net"})],
                )
            ],
        )
    )
    created_event = created["notification"]["group_event"]
    assert created_event["kind"] == "membership_requests"
    assert created_event["action"] == "created"
    assert created_event["request_method"] == "invite_link"
    assert created_event["participants"] == ["user@s.whatsapp.net"]

    revoked = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={
                "id": "nid-g-8",
                "from": "999@g.us",
                "type": "w:gp2",
                "participant": "user@s.whatsapp.net",
            },
            content=[
                BinaryNode(
                    tag="revoked_membership_requests",
                    attrs={},
                    content=[BinaryNode(tag="participant", attrs={"jid": "user@s.whatsapp.net"})],
                )
            ],
        )
    )
    revoked_event = revoked["notification"]["group_event"]
    assert revoked_event["kind"] == "membership_requests"
    assert revoked_event["action"] == "revoked"

    rejected = decode_notification_node(
        BinaryNode(
            tag="notification",
            attrs={
                "id": "nid-g-9",
                "from": "999@g.us",
                "type": "w:gp2",
                "participant": "admin@s.whatsapp.net",
            },
            content=[
                BinaryNode(
                    tag="revoked_membership_requests",
                    attrs={},
                    content=[BinaryNode(tag="participant", attrs={"jid": "user@s.whatsapp.net"})],
                )
            ],
        )
    )
    rejected_event = rejected["notification"]["group_event"]
    assert rejected_event["kind"] == "membership_requests"
    assert rejected_event["action"] == "rejected"


def test_decode_newsletter_notification_reaction_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "nid-news-1", "from": "12345@newsletter", "participant": "111@s.whatsapp.net"},
        content=[
            BinaryNode(
                tag="reaction",
                attrs={"message_id": "srv-1"},
                content=[BinaryNode(tag="reaction", attrs={}, content=b"\xf0\x9f\x91\x8d")],
            )
        ],
    )
    event = decode_notification_node(node)
    newsletter_event = event["notification"]["newsletter_event"]
    assert newsletter_event["type"] == "reaction"
    assert newsletter_event["newsletter_jid"] == "12345@newsletter"
    assert newsletter_event["message_id"] == "srv-1"
    assert newsletter_event["reaction"] == "👍"


def test_decode_newsletter_notification_view_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "nid-news-2", "from": "12345@newsletter"},
        content=[BinaryNode(tag="view", attrs={"message_id": "srv-2"}, content=b"42")],
    )
    event = decode_notification_node(node)
    newsletter_event = event["notification"]["newsletter_event"]
    assert newsletter_event["type"] == "view"
    assert newsletter_event["newsletter_jid"] == "12345@newsletter"
    assert newsletter_event["message_id"] == "srv-2"
    assert newsletter_event["count"] == 42


def test_decode_newsletter_notification_participant_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "nid-news-3", "from": "12345@newsletter", "participant": "admin@s.whatsapp.net"},
        content=[
            BinaryNode(
                tag="participant",
                attrs={"jid": "member@s.whatsapp.net", "action": "promote", "role": "ADMIN"},
            )
        ],
    )
    event = decode_notification_node(node)
    newsletter_event = event["notification"]["newsletter_event"]
    assert newsletter_event["type"] == "participant"
    assert newsletter_event["newsletter_jid"] == "12345@newsletter"
    assert newsletter_event["user"] == "member@s.whatsapp.net"
    assert newsletter_event["action"] == "promote"
    assert newsletter_event["new_role"] == "ADMIN"
    assert newsletter_event["author"] == "admin@s.whatsapp.net"


def test_decode_newsletter_notification_update_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "nid-news-4", "from": "12345@newsletter", "participant": "admin@s.whatsapp.net"},
        content=[
            BinaryNode(
                tag="update",
                attrs={},
                content=[
                    BinaryNode(
                        tag="settings",
                        attrs={},
                        content=[
                            BinaryNode(tag="name", attrs={}, content=b"New Name"),
                            BinaryNode(tag="description", attrs={}, content=b"New Desc"),
                        ],
                    )
                ],
            )
        ],
    )
    event = decode_notification_node(node)
    newsletter_event = event["notification"]["newsletter_event"]
    assert newsletter_event["type"] == "settings_update"
    assert newsletter_event["newsletter_jid"] == "12345@newsletter"
    assert newsletter_event["update"] == {"name": "New Name", "description": "New Desc"}
    assert newsletter_event["author"] == "admin@s.whatsapp.net"


def test_decode_call_node_offer_event() -> None:
    node = BinaryNode(
        tag="call",
        attrs={"from": "123@s.whatsapp.net", "t": "123", "offline": "true"},
        content=[
            BinaryNode(
                tag="offer",
                attrs={"call-id": "call-1", "from": "123@s.whatsapp.net", "type": "group", "group-jid": "444@g.us"},
                content=[BinaryNode(tag="video", attrs={})],
            )
        ],
    )
    event = decode_call_node(node)
    assert event["type"] == "messages.call"
    assert event["call"]["id"] == "call-1"
    assert event["call"]["from"] == "123@s.whatsapp.net"
    assert event["call"]["chat_id"] == "123@s.whatsapp.net"
    assert event["call"]["status"] == "offer"
    assert event["call"]["is_video"] is True
    assert event["call"]["is_group"] is True
    assert event["call"]["group_jid"] == "444@g.us"
    assert event["call"]["timestamp"] == 123
    assert event["call"]["offline"] is True


def test_decode_call_node_offline_false_string_maps_false() -> None:
    node = BinaryNode(
        tag="call",
        attrs={"from": "123@s.whatsapp.net", "t": "124", "offline": "false"},
        content=[BinaryNode(tag="terminate", attrs={"call-id": "call-2", "call-creator": "456@s.whatsapp.net"})],
    )
    event = decode_call_node(node)
    assert event["call"]["status"] == "terminate"
    assert event["call"]["from"] == "456@s.whatsapp.net"
    assert event["call"]["offline"] is False


def test_decode_ack_error_maps_to_bad_ack_event() -> None:
    event = decode_ack_node(
        BinaryNode(
            tag="ack",
            attrs={
                "class": "message",
                "from": "777@s.whatsapp.net",
                "id": "m-777",
                "error": "475",
                "phash": "2:abc",
            },
        )
    )
    assert event["type"] == "messages.bad_ack"
    assert event["bad_ack"]["message_id"] == "m-777"
    assert event["bad_ack"]["error"] == "475"
    assert event["bad_ack"]["phash"] == "2:abc"


def test_build_message_ack_copies_routing_attrs() -> None:
    node = BinaryNode(
        tag="message",
        attrs={
            "from": "444@s.whatsapp.net",
            "id": "msg-44",
            "participant": "444:1@s.whatsapp.net",
            "recipient": "555@s.whatsapp.net",
            "type": "text",
            "t": "101",
        },
    )
    ack = build_message_ack(node)
    assert ack.tag == "ack"
    assert ack.attrs["to"] == "444@s.whatsapp.net"
    assert ack.attrs["id"] == "msg-44"
    assert ack.attrs["class"] == "message"
    assert ack.attrs["participant"] == "444:1@s.whatsapp.net"
    assert ack.attrs["recipient"] == "555@s.whatsapp.net"
    assert ack.attrs["type"] == "text"
    assert ack.attrs["t"] == "101"


def test_build_retry_receipt_node_shape() -> None:
    original = BinaryNode(
        tag="message",
        attrs={
            "id": "m-100",
            "from": "111@s.whatsapp.net",
            "participant": "111:1@s.whatsapp.net",
            "t": "55",
        },
    )
    retry = build_retry_receipt_node(original, retry_count=2, timestamp=200)
    assert retry.tag == "receipt"
    assert retry.attrs["to"] == "111@s.whatsapp.net"
    assert retry.attrs["id"] == "m-100"
    assert retry.attrs["type"] == "retry"
    assert retry.attrs["participant"] == "111:1@s.whatsapp.net"
    assert isinstance(retry.content, list)
    retry_child = retry.content[0]
    assert retry_child.tag == "retry"
    assert retry_child.attrs["count"] == "2"
    assert retry_child.attrs["id"] == "m-100"
    assert retry_child.attrs["t"] == "200"
    assert retry_child.attrs["v"] == "1"


@pytest.mark.asyncio
async def test_normalize_incoming_node_dispatches_receipt() -> None:
    class FakeRepo:
        async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
            del jid, type_str, ciphertext
            return b""

    event = await normalize_incoming_node(
        BinaryNode(tag="receipt", attrs={"id": "r-1", "from": "777@s.whatsapp.net"}),
        FakeRepo(),
    )
    assert event is not None
    assert event["type"] == "messages.receipt"


@pytest.mark.asyncio
async def test_normalize_incoming_node_dispatches_bad_ack() -> None:
    event = await normalize_incoming_node(
        BinaryNode(tag="ack", attrs={"class": "message", "from": "a@s.whatsapp.net", "id": "1", "error": "500"}),
        None,
    )
    assert event is not None
    assert event["type"] == "messages.bad_ack"


@pytest.mark.asyncio
async def test_normalize_incoming_node_dispatches_call() -> None:
    event = await normalize_incoming_node(
        BinaryNode(
            tag="call",
            attrs={"from": "123@s.whatsapp.net", "t": "12"},
            content=[BinaryNode(tag="offer", attrs={"call-id": "call-2", "from": "123@s.whatsapp.net"})],
        ),
        None,
    )
    assert event is not None
    assert event["type"] == "messages.call"


def test_unpad_random_max16_behaviour() -> None:
    data = b"abc" + bytes([2, 2])
    assert _unpad_random_max16(data) == b"abc"
    assert _unpad_random_max16(b"") == b""
    assert _unpad_random_max16(b"\x00") == b"\x00"
