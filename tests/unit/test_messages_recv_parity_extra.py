from __future__ import annotations

import pytest

from waton.client.messages_recv import (
    OfflineNodeProcessor,
    build_call_reject_node,
    build_placeholder_resend_request,
    drain_nodes_with_buffer,
    decode_notification_node,
)
from waton.protocol.binary_node import BinaryNode


def test_decode_notification_encrypt_identity_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "n1", "from": "s.whatsapp.net", "type": "encrypt"},
        content=[
            BinaryNode(
                tag="identity",
                attrs={"jid": "123@s.whatsapp.net"},
                content=[BinaryNode(tag="device-identity", attrs={"key-index": "7"}, content=b"abc")],
            )
        ],
    )
    event = decode_notification_node(node)
    encrypt_event = event["notification"]["encrypt_event"]
    assert encrypt_event["type"] == "identity"
    assert encrypt_event["jid"] == "123@s.whatsapp.net"
    assert encrypt_event["device_identity_key_index"] == "7"
    assert encrypt_event["has_device_identity"] is True


def test_decode_notification_link_code_companion_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "n2", "from": "s.whatsapp.net", "type": "link_code_companion_reg"},
        content=[
            BinaryNode(
                tag="link_code_pairing_wrapped_companion_ephemeral_pub",
                attrs={},
                content=b"\x01\x02\x03",
            ),
            BinaryNode(
                tag="companion_server_auth_key_pub",
                attrs={},
                content=b"\xAA\xBB",
            ),
            BinaryNode(tag="primary_identity_pub", attrs={}, content=b"\xCC"),
            BinaryNode(tag="adv_secret", attrs={}, content=b"\xDD\xEE"),
        ],
    )
    event = decode_notification_node(node)
    link_code_event = event["notification"]["link_code_event"]
    assert link_code_event["type"] == "link_code_companion_reg"
    assert link_code_event["ephemeral_pub_b64"] == "AQID"
    assert link_code_event["companion_server_auth_key_pub_b64"] == "qrs="
    assert link_code_event["primary_identity_pub_b64"] == "zA=="
    assert link_code_event["adv_secret_b64"] == "3e4="


def test_decode_notification_privacy_token_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "n3", "from": "s.whatsapp.net", "type": "privacy_token"},
        content=[
            BinaryNode(
                tag="privacy_token",
                attrs={},
                content=[
                    BinaryNode(tag="token", attrs={"jid": "123@s.whatsapp.net"}, content=b"tok1"),
                    BinaryNode(tag="token", attrs={"jid": "999@g.us"}, content=b"tok2"),
                ],
            )
        ],
    )
    event = decode_notification_node(node)
    privacy_event = event["notification"]["privacy_token_event"]
    assert privacy_event["type"] == "privacy_token"
    assert privacy_event["tokens"] == {
        "123@s.whatsapp.net": "dG9rMQ==",
        "999@g.us": "dG9rMg==",
    }


def test_decode_notification_mediaretry_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "n4", "from": "s.whatsapp.net", "type": "mediaretry"},
        content=[
            BinaryNode(
                tag="mediaretry",
                attrs={"id": "mid-1", "to": "123@s.whatsapp.net"},
                content=[
                    BinaryNode(tag="result", attrs={"code": "200"}, content=b"ok"),
                    BinaryNode(tag="direct_path", attrs={}, content=b"/v/t62"),
                ],
            )
        ],
    )
    event = decode_notification_node(node)
    mediaretry_event = event["notification"]["media_retry_event"]
    assert mediaretry_event["type"] == "mediaretry"
    assert mediaretry_event["message_id"] == "mid-1"
    assert mediaretry_event["to"] == "123@s.whatsapp.net"
    assert mediaretry_event["result_code"] == "200"
    assert mediaretry_event["result_payload_b64"] == "b2s="
    assert mediaretry_event["direct_path"] == "/v/t62"


def test_decode_notification_history_sync_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "n5", "from": "s.whatsapp.net", "type": "history"},
        content=[
            BinaryNode(
                tag="history",
                attrs={"sync_type": "full", "chunk_order": "3", "progress": "80", "oldest_msg_timestamp": "123"},
                content=b"chunk-data",
            )
        ],
    )
    event = decode_notification_node(node)
    history_event = event["notification"]["history_sync_event"]
    assert history_event["type"] == "history_sync"
    assert history_event["sync_type"] == "full"
    assert history_event["chunk_order"] == 3
    assert history_event["progress"] == 80
    assert history_event["oldest_msg_timestamp"] == 123
    assert history_event["payload_b64"] == "Y2h1bmstZGF0YQ=="


def test_decode_notification_account_sync_event() -> None:
    node = BinaryNode(
        tag="notification",
        attrs={"id": "n6", "from": "s.whatsapp.net", "type": "account_sync"},
        content=[
            BinaryNode(
                tag="devices",
                attrs={},
                content=[
                    BinaryNode(
                        tag="device",
                        attrs={
                            "jid": "123:1@s.whatsapp.net",
                            "platform": "android",
                            "last_active": "170000",
                            "trusted": "1",
                        },
                    )
                ],
            )
        ],
    )
    event = decode_notification_node(node)
    account_event = event["notification"]["account_sync_event"]
    assert account_event["type"] == "account_sync"
    assert account_event["action"] == "devices"
    assert account_event["linked_devices"][0]["jid"] == "123:1@s.whatsapp.net"
    assert account_event["linked_devices"][0]["platform"] == "android"
    assert account_event["linked_devices"][0]["is_trusted"] is True


def test_build_call_reject_node_shape() -> None:
    reject = build_call_reject_node(call_id="call-1", call_from="123@s.whatsapp.net", timestamp=1700000000)
    assert reject.tag == "call"
    assert reject.attrs["to"] == "123@s.whatsapp.net"
    assert reject.attrs["id"] == "call-1"
    assert reject.attrs["t"] == "1700000000"
    assert isinstance(reject.content, list)
    reject_child = reject.content[0]
    assert reject_child.tag == "reject"
    assert reject_child.attrs["call-id"] == "call-1"
    assert reject_child.attrs["call-creator"] == "123@s.whatsapp.net"


def test_build_placeholder_resend_request_shape() -> None:
    resend = build_placeholder_resend_request(
        message_id="m-1",
        remote_jid="123@s.whatsapp.net",
        participant="123:1@s.whatsapp.net",
    )
    assert resend.tag == "iq"
    assert resend.attrs["type"] == "set"
    assert resend.attrs["xmlns"] == "placeholder"
    assert isinstance(resend.content, list)
    placeholder = resend.content[0]
    assert placeholder.tag == "placeholder"
    item = placeholder.content[0]
    assert item.tag == "item"
    assert item.attrs["id"] == "m-1"
    assert item.attrs["jid"] == "123@s.whatsapp.net"
    assert item.attrs["participant"] == "123:1@s.whatsapp.net"


@pytest.mark.asyncio
async def test_offline_node_processor_priority_order() -> None:
    processor = OfflineNodeProcessor()
    processor.enqueue(BinaryNode(tag="message", attrs={"id": "m1"}))
    processor.enqueue(BinaryNode(tag="notification", attrs={"id": "n1"}))
    processor.enqueue(BinaryNode(tag="receipt", attrs={"id": "r1"}))

    seen: list[str] = []

    async def _handler(node: BinaryNode) -> None:
        seen.append(node.tag)

    processed = await processor.drain(_handler, yield_every=0)
    assert processed == 3
    assert seen == ["receipt", "notification", "message"]


@pytest.mark.asyncio
async def test_drain_nodes_with_buffer_limits_queue() -> None:
    nodes = [
        BinaryNode(tag="message", attrs={"id": "m1"}),
        BinaryNode(tag="message", attrs={"id": "m2"}),
        BinaryNode(tag="receipt", attrs={"id": "r1"}),
    ]
    seen: list[str] = []

    async def _handler(node: BinaryNode) -> None:
        seen.append(node.attrs.get("id", ""))

    processed = await drain_nodes_with_buffer(nodes, _handler, max_queue_size=2, yield_every=0)
    assert processed == 2
    assert seen == ["r1", "m2"]
