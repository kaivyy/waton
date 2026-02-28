import asyncio
import base64
from typing import Any

import pytest

from waton.client.client import WAClient
from waton.core.errors import ConnectionError as WatonConnectionError
from waton.protocol.binary_node import BinaryNode
from waton.protocol.noise_handler import NoiseHandler
from waton.protocol.protobuf.wire import _encode_len_delimited, _encode_string, _encode_varint_field
from waton.utils.auth import init_auth_creds
from waton.utils.crypto import generate_keypair


class _DummyStorage:
    def __init__(self) -> None:
        self.creds: Any = None

    async def get_creds(self) -> Any:
        return self.creds

    async def save_creds(self, creds: Any) -> None:
        self.creds = creds

    async def get_session(self, jid: str) -> bytes | None:
        return None

    async def save_session(self, jid: str, data: bytes) -> None:
        return None

    async def get_prekey(self, key_id: int) -> bytes | None:
        return None

    async def save_prekey(self, key_id: int, data: bytes) -> None:
        return None

    async def get_sender_key(self, group_jid: str, sender_jid: str) -> bytes | None:
        return None

    async def save_sender_key(self, group_jid: str, sender_jid: str, data: bytes) -> None:
        return None


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_handle_raw_ws_message_queues_handshake_frame() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        client.noise = NoiseHandler(generate_keypair())
        await client._handle_raw_ws_message(b"\x00\x00\x03abc")
        queued = await client._raw_frame_queue.get()
        assert queued == b"abc"

    _run(_case())


def test_pair_device_generates_qr_event() -> None:
    async def _case() -> None:
        storage = _DummyStorage()
        client = WAClient(storage)
        client.creds = init_auth_creds()

        sent_nodes: list[BinaryNode] = []
        events = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: Any) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_connection_update = _capture_event

        stanza = BinaryNode(
            tag="iq",
            attrs={"id": "abc", "type": "set"},
            content=[
                BinaryNode(
                    tag="pair-device",
                    attrs={},
                    content=[BinaryNode(tag="ref", attrs={}, content=b"ref-token-1")],
                )
            ],
        )
        await client._handle_pair_device(stanza)
        await asyncio.sleep(0)

        assert sent_nodes
        assert sent_nodes[0].tag == "iq"
        assert events
        assert events[0].qr and events[0].qr.startswith("ref-token-1,")

        if client._qr_task:
            client._qr_task.cancel()

    _run(_case())


def test_stream_error_reason_forwarded_on_disconnect() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), auto_restart_on_515=False)
        events = []
        disconnects: list[Exception] = []
        seen_nodes: list[BinaryNode] = []

        async def _capture_event(event: Any) -> None:
            events.append(event)

        async def _capture_disconnect(exc: Exception) -> None:
            disconnects.append(exc)

        async def _capture_message(node: BinaryNode) -> None:
            seen_nodes.append(node)

        client.on_connection_update = _capture_event
        client.on_disconnected = _capture_disconnect
        client.on_message = _capture_message

        await client._handle_binary_node(
            BinaryNode(
                tag="stream:error",
                attrs={"code": "515"},
                content=[BinaryNode(tag="conflict", attrs={})],
            )
        )
        await client._handle_ws_disconnect(Exception("raw close"))

        assert seen_nodes and seen_nodes[0].tag == "stream:error"
        assert events and events[-1].status == "close"
        assert isinstance(events[-1].reason, WatonConnectionError)
        assert events[-1].reason.status_code == 515
        assert disconnects and isinstance(disconnects[-1], WatonConnectionError)
        assert disconnects[-1].status_code == 515

    _run(_case())


def test_failure_reason_forwarded_on_disconnect() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        events = []
        disconnects: list[Exception] = []

        async def _capture_event(event: Any) -> None:
            events.append(event)

        async def _capture_disconnect(exc: Exception) -> None:
            disconnects.append(exc)

        client.on_connection_update = _capture_event
        client.on_disconnected = _capture_disconnect

        await client._handle_binary_node(BinaryNode(tag="failure", attrs={"reason": "401"}))
        await client._handle_ws_disconnect(Exception("raw close"))

        assert events and events[-1].status == "close"
        assert isinstance(events[-1].reason, WatonConnectionError)
        assert events[-1].reason.status_code == 401
        assert disconnects and isinstance(disconnects[-1], WatonConnectionError)
        assert disconnects[-1].status_code == 401

    _run(_case())


def test_restart_required_disconnect_reconnects_once() -> None:
    async def _case() -> None:
        storage = _DummyStorage()
        storage.creds = init_auth_creds()
        storage.creds.registered = True
        storage.creds.me = {"id": "628123456789:1@s.whatsapp.net"}
        client = WAClient(
            storage,
            auto_restart_on_515=True,
            max_restart_attempts=1,
        )

        reconnect_calls: list[str] = []
        disconnects: list[Exception] = []

        async def _fake_connect() -> None:
            reconnect_calls.append("connect")

        async def _capture_disconnect(exc: Exception) -> None:
            disconnects.append(exc)

        client.connect = _fake_connect  # type: ignore[method-assign]
        client.on_disconnected = _capture_disconnect

        await client._handle_binary_node(BinaryNode(tag="stream:error", attrs={"code": "515"}))
        await client._handle_ws_disconnect(Exception("raw close"))

        assert reconnect_calls == ["connect"]
        assert disconnects == []

    _run(_case())


def test_handle_raw_ws_message_applies_offline_buffer_priority() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), enable_offline_node_buffer=True)

        class _Noise:
            def decode_frame(self, data: bytes) -> list[BinaryNode]:
                del data
                return [
                    BinaryNode(tag="message", attrs={"id": "m-1"}),
                    BinaryNode(tag="notification", attrs={"id": "n-1"}),
                    BinaryNode(tag="receipt", attrs={"id": "r-1"}),
                ]

        seen: list[str] = []

        async def _capture(node: BinaryNode) -> None:
            seen.append(node.tag)

        client.noise = _Noise()  # type: ignore[assignment]
        client._handle_binary_node = _capture  # type: ignore[method-assign]
        await client._handle_raw_ws_message(b"frame")

        assert seen == ["receipt", "notification", "message"]

    _run(_case())


def test_handle_raw_ws_message_buffer_can_be_disabled() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), enable_offline_node_buffer=False)

        class _Noise:
            def decode_frame(self, data: bytes) -> list[BinaryNode]:
                del data
                return [
                    BinaryNode(tag="message", attrs={"id": "m-1"}),
                    BinaryNode(tag="notification", attrs={"id": "n-1"}),
                    BinaryNode(tag="receipt", attrs={"id": "r-1"}),
                ]

        seen: list[str] = []

        async def _capture(node: BinaryNode) -> None:
            seen.append(node.tag)

        client.noise = _Noise()  # type: ignore[assignment]
        client._handle_binary_node = _capture  # type: ignore[method-assign]
        await client._handle_raw_ws_message(b"frame")

        assert seen == ["message", "notification", "receipt"]

    _run(_case())


def test_receipt_node_emits_normalized_event_and_ack() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())
        seen_events: list[dict[str, Any]] = []
        sent_nodes: list[BinaryNode] = []
        seen_nodes: list[BinaryNode] = []

        async def _capture_event(event: dict[str, Any]) -> None:
            seen_events.append(event)

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_message(node: BinaryNode) -> None:
            seen_nodes.append(node)

        client.on_event = _capture_event
        client.on_message = _capture_message
        client.send_node = _capture_send  # type: ignore[method-assign]

        receipt = BinaryNode(
            tag="receipt",
            attrs={"id": "r-1", "from": "123@s.whatsapp.net", "type": "read"},
            content=[BinaryNode(tag="item", attrs={"id": "mid-1"})],
        )
        await client._handle_binary_node(receipt)

        assert seen_nodes and seen_nodes[0].tag == "receipt"
        assert seen_events and seen_events[0]["type"] == "messages.receipt"
        assert sent_nodes and sent_nodes[0].tag == "ack"
        assert sent_nodes[0].attrs["class"] == "receipt"
        assert sent_nodes[0].attrs["id"] == "r-1"

    _run(_case())


def test_call_node_emits_normalized_event_and_ack() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())
        seen_events: list[dict[str, Any]] = []
        sent_nodes: list[BinaryNode] = []
        seen_nodes: list[BinaryNode] = []

        async def _capture_event(event: dict[str, Any]) -> None:
            seen_events.append(event)

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_message(node: BinaryNode) -> None:
            seen_nodes.append(node)

        client.on_event = _capture_event
        client.on_message = _capture_message
        client.send_node = _capture_send  # type: ignore[method-assign]

        call_node = BinaryNode(
            tag="call",
            attrs={"from": "123@s.whatsapp.net", "t": "12"},
            content=[BinaryNode(tag="offer", attrs={"call-id": "call-1", "from": "123@s.whatsapp.net"})],
        )
        await client._handle_binary_node(call_node)

        assert seen_nodes and seen_nodes[0].tag == "call"
        assert seen_events and seen_events[0]["type"] == "messages.call"
        assert sent_nodes and sent_nodes[0].tag == "ack"
        assert sent_nodes[0].attrs["class"] == "call"

    _run(_case())


def test_call_node_auto_reject_enabled_sends_reject() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), auto_reject_calls=True)
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())
        seen_events: list[dict[str, Any]] = []
        sent_nodes: list[BinaryNode] = []

        async def _capture_event(event: dict[str, Any]) -> None:
            seen_events.append(event)

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        client.on_event = _capture_event
        client.send_node = _capture_send  # type: ignore[method-assign]

        call_node = BinaryNode(
            tag="call",
            attrs={"from": "123@s.whatsapp.net", "t": "12"},
            content=[BinaryNode(tag="offer", attrs={"call-id": "call-1", "from": "123@s.whatsapp.net"})],
        )
        await client._handle_binary_node(call_node)

        assert seen_events and seen_events[0]["type"] == "messages.call"
        assert seen_events[0]["call_reject_sent"] is True

        reject_nodes = [n for n in sent_nodes if n.tag == "call"]
        assert reject_nodes
        reject = reject_nodes[0]
        assert reject.attrs["to"] == "123@s.whatsapp.net"
        assert reject.attrs["id"] == "call-1"
        assert isinstance(reject.content, list)
        assert reject.content[0].tag == "reject"

    _run(_case())


def test_auto_ack_can_be_disabled() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), auto_ack_incoming=False)
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())
        sent_nodes: list[BinaryNode] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        client.send_node = _capture_send  # type: ignore[method-assign]

        await client._handle_binary_node(BinaryNode(tag="receipt", attrs={"id": "r-2", "from": "123@s.whatsapp.net"}))
        assert sent_nodes == []

    _run(_case())


def test_bad_ack_emits_bad_ack_event_without_sending_ack() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())
        sent_nodes: list[BinaryNode] = []
        events: list[dict[str, Any]] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_event = _capture_event

        await client._handle_binary_node(
            BinaryNode(
                tag="ack",
                attrs={"class": "message", "from": "123@s.whatsapp.net", "id": "m1", "error": "479"},
            )
        )

        assert events and events[0]["type"] == "messages.bad_ack"
        assert sent_nodes == []

    _run(_case())


def test_receipt_ack_marks_retry_entry_acked() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        events: list[dict[str, Any]] = []

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.on_event = _capture_event
        client.retry_manager.register_retry("m-retry-acked")
        assert client.retry_manager.should_retry("m-retry-acked") is True

        await client._handle_binary_node(
            BinaryNode(
                tag="ack",
                attrs={"class": "receipt", "id": "m-retry-acked", "from": "123@s.whatsapp.net"},
            )
        )

        assert events and events[0]["type"] == "messages.ack"
        assert client.retry_manager.should_retry("m-retry-acked") is False

    _run(_case())


def test_retry_receipt_event_is_annotated_with_retry_decisions() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), max_retry_receipts=1)
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())
        events: list[dict[str, Any]] = []

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.on_event = _capture_event

        retry_receipt = BinaryNode(
            tag="receipt",
            attrs={
                "id": "m-retry",
                "from": "123@s.whatsapp.net",
                "participant": "123:1@s.whatsapp.net",
                "type": "retry",
            },
            content=[
                BinaryNode(tag="retry", attrs={"count": "1", "id": "m-retry"}),
                BinaryNode(tag="item", attrs={"id": "m-retry"}),
            ],
        )
        await client._handle_binary_node(retry_receipt)
        await client._handle_binary_node(retry_receipt)

        assert len(events) == 2
        assert events[0]["type"] == "messages.retry_request"
        assert events[0]["retry_allowed"] is True
        assert events[1]["retry_allowed"] is False

    _run(_case())


def test_retry_receipt_resends_cached_message() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), max_retry_receipts=2, auto_ack_incoming=False)
        sent_nodes: list[BinaryNode] = []
        events: list[dict[str, Any]] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_event = _capture_event

        client._remember_sent_message(
            BinaryNode(
                tag="message",
                attrs={"to": "123@s.whatsapp.net", "id": "m-resend", "type": "text"},
                content=[BinaryNode(tag="participants", attrs={}, content=[])],
            )
        )

        await client._handle_binary_node(
            BinaryNode(
                tag="receipt",
                attrs={
                    "id": "m-resend",
                    "from": "123@s.whatsapp.net",
                    "participant": "123:1@s.whatsapp.net",
                    "type": "retry",
                },
                content=[BinaryNode(tag="retry", attrs={"count": "1", "id": "m-resend"})],
            )
        )

        assert sent_nodes and sent_nodes[0].tag == "message"
        assert sent_nodes[0].attrs["id"] == "m-resend"
        assert events and events[0]["retry_resend"]["sent_ids"] == ["m-resend"]

    _run(_case())


def test_retry_receipt_reports_missing_cached_message() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), max_retry_receipts=2, auto_ack_incoming=False)
        sent_nodes: list[BinaryNode] = []
        events: list[dict[str, Any]] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_event = _capture_event

        await client._handle_binary_node(
            BinaryNode(
                tag="receipt",
                attrs={
                    "id": "m-missing",
                    "from": "123@s.whatsapp.net",
                    "participant": "123:1@s.whatsapp.net",
                    "type": "retry",
                },
                content=[BinaryNode(tag="retry", attrs={"count": "1", "id": "m-missing"})],
            )
        )

        assert sent_nodes == []
        assert events and events[0]["retry_resend"]["missing_ids"] == ["m-missing"]

    _run(_case())


def test_recent_sent_message_cache_respects_limit() -> None:
    client = WAClient(_DummyStorage(), max_recent_sent_messages=1)
    client._remember_sent_message(BinaryNode(tag="message", attrs={"id": "m1"}, content=[]))
    client._remember_sent_message(BinaryNode(tag="message", attrs={"id": "m2"}, content=[]))

    assert "m1" not in client._recent_sent_messages
    assert "m2" in client._recent_sent_messages


def test_decrypt_error_sends_retry_receipt_event(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), auto_ack_incoming=False, max_decrypt_retry_requests=2)
        client.creds = init_auth_creds()
        sent_nodes: list[BinaryNode] = []
        events: list[dict[str, Any]] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_event = _capture_event

        async def _raise_decrypt(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise ValueError("decrypt failed")

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _raise_decrypt)

        await client._handle_binary_node(
            BinaryNode(
                tag="message",
                attrs={"id": "m-decrypt", "from": "222@s.whatsapp.net", "participant": "222:1@s.whatsapp.net"},
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            )
        )

        assert sent_nodes and sent_nodes[0].tag == "receipt"
        assert sent_nodes[0].attrs["type"] == "retry"
        assert events and events[0]["type"] == "messages.retry_request_sent"
        assert events[0]["retry_request"]["sent"] is True
        assert events[0]["retry_request"]["count"] == 1

    _run(_case())


def test_decrypt_error_sends_placeholder_resend_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        client = WAClient(
            _DummyStorage(),
            auto_ack_incoming=False,
            max_decrypt_retry_requests=2,
            enable_placeholder_resend=True,
        )
        client.creds = init_auth_creds()
        sent_nodes: list[BinaryNode] = []
        events: list[dict[str, Any]] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_event = _capture_event

        async def _raise_decrypt(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise ValueError("decrypt failed")

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _raise_decrypt)

        await client._handle_binary_node(
            BinaryNode(
                tag="message",
                attrs={"id": "m-placeholder", "from": "222@s.whatsapp.net", "participant": "222:1@s.whatsapp.net"},
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            )
        )

        assert sent_nodes and sent_nodes[0].tag == "receipt"
        placeholder_nodes = [node for node in sent_nodes if node.tag == "iq" and node.attrs.get("xmlns") == "placeholder"]
        assert placeholder_nodes
        assert events and events[0]["retry_request"]["placeholder_sent"] is True

    _run(_case())


def test_decrypt_error_placeholder_resend_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        client = WAClient(
            _DummyStorage(),
            auto_ack_incoming=False,
            max_decrypt_retry_requests=2,
            enable_placeholder_resend=False,
        )
        client.creds = init_auth_creds()
        sent_nodes: list[BinaryNode] = []
        events: list[dict[str, Any]] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_event = _capture_event

        async def _raise_decrypt(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise ValueError("decrypt failed")

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _raise_decrypt)

        await client._handle_binary_node(
            BinaryNode(
                tag="message",
                attrs={"id": "m-placeholder-off", "from": "333@s.whatsapp.net"},
                content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
            )
        )

        assert sent_nodes and sent_nodes[0].tag == "receipt"
        placeholder_nodes = [node for node in sent_nodes if node.tag == "iq" and node.attrs.get("xmlns") == "placeholder"]
        assert placeholder_nodes == []
        assert events and events[0]["retry_request"]["sent"] is True
        assert events[0]["retry_request"]["placeholder_sent"] is False

    _run(_case())


def test_decrypt_error_retry_limit_respected(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage(), auto_ack_incoming=False, max_decrypt_retry_requests=1)
        client.creds = init_auth_creds()
        sent_nodes: list[BinaryNode] = []
        events: list[dict[str, Any]] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_event = _capture_event

        async def _raise_decrypt(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise ValueError("decrypt failed")

        monkeypatch.setattr("waton.protocol.signal_repo.SignalRepository.decrypt_message", _raise_decrypt)

        failing_node = BinaryNode(
            tag="message",
            attrs={"id": "m-limit", "from": "333@s.whatsapp.net"},
            content=[BinaryNode(tag="enc", attrs={"type": "msg", "v": "2"}, content=b"cipher")],
        )
        await client._handle_binary_node(failing_node)
        await client._handle_binary_node(failing_node)

        assert len(sent_nodes) == 1
        assert len(events) == 2
        assert events[0]["retry_request"]["sent"] is True
        assert events[1]["retry_request"]["sent"] is False

    _run(_case())


def test_retry_receipt_requests_placeholder_for_retry_ids() -> None:
    async def _case() -> None:
        client = WAClient(
            _DummyStorage(),
            max_retry_receipts=2,
            auto_ack_incoming=False,
            placeholder_resend_on_retry=True,
        )
        sent_nodes: list[BinaryNode] = []
        events: list[dict[str, Any]] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.on_event = _capture_event

        await client._handle_binary_node(
            BinaryNode(
                tag="receipt",
                attrs={
                    "id": "m-placeholder-retry",
                    "from": "123@s.whatsapp.net",
                    "participant": "123:1@s.whatsapp.net",
                    "type": "retry",
                },
                content=[BinaryNode(tag="retry", attrs={"count": "1", "id": "m-placeholder-retry"})],
            )
        )

        placeholder_nodes = [node for node in sent_nodes if node.tag == "iq" and node.attrs.get("xmlns") == "placeholder"]
        assert placeholder_nodes
        assert events and events[0]["retry_resend"]["placeholder_sent_ids"] == ["m-placeholder-retry"]

    _run(_case())


def test_protocol_app_state_key_share_saved_to_creds() -> None:
    async def _case() -> None:
        storage = _DummyStorage()
        storage.creds = init_auth_creds()
        client = WAClient(storage, auto_ack_incoming=False)
        client.creds = storage.creds
        events: list[dict[str, Any]] = []

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.on_event = _capture_event

        key_id_payload = _encode_len_delimited(1, b"key-1")
        key_data_payload = _encode_len_delimited(1, b"\x11" * 32)
        key_item_payload = _encode_len_delimited(1, key_id_payload) + _encode_len_delimited(2, key_data_payload)
        share_payload = _encode_len_delimited(1, key_item_payload)
        protocol_payload = _encode_varint_field(2, 6) + _encode_len_delimited(7, share_payload)
        message_payload = _encode_len_delimited(12, protocol_payload)

        await client._handle_binary_node(
            BinaryNode(
                tag="message",
                attrs={"id": "m-app-state", "from": "123@s.whatsapp.net"},
                content=message_payload,
            )
        )

        assert events and events[0]["type"] == "messages.app_state_sync_key_share"
        key_id = base64.b64encode(b"key-1").decode("ascii")
        assert storage.creds.additional_data is not None
        stored = storage.creds.additional_data["app_state_sync_keys"]
        assert key_id in stored
        assert stored[key_id]["key_data_size"] == 32
        assert events[0]["app_state_sync_keys_saved"] == 1

    _run(_case())


def test_protocol_history_sync_appends_processed_history_record() -> None:
    async def _case() -> None:
        storage = _DummyStorage()
        storage.creds = init_auth_creds()
        client = WAClient(storage, auto_ack_incoming=False)
        client.creds = storage.creds
        events: list[dict[str, Any]] = []

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        client.on_event = _capture_event

        history_payload = (
            _encode_varint_field(6, 6)  # ON_DEMAND
            + _encode_varint_field(7, 2)  # chunk_order
            + _encode_varint_field(9, 80)  # progress
            + _encode_varint_field(10, 123456)  # oldest timestamp
            + _encode_string(12, "session-1")
        )
        protocol_payload = _encode_varint_field(2, 5) + _encode_len_delimited(6, history_payload)
        message_payload = _encode_len_delimited(12, protocol_payload)

        message_node = BinaryNode(
            tag="message",
            attrs={"id": "m-history", "from": "123@s.whatsapp.net", "t": "100"},
            content=message_payload,
        )
        await client._handle_binary_node(message_node)
        await client._handle_binary_node(message_node)

        assert len(events) == 2
        assert events[0]["type"] == "messages.history_sync"
        assert storage.creds.processed_history_messages is not None
        assert len(storage.creds.processed_history_messages) == 1
        first = storage.creds.processed_history_messages[0]
        assert first["id"] == "m-history"
        assert first["sync_type"] == 6
        assert first["chunk_order"] == 2
        assert events[0]["history_processed_count"] == 1

    _run(_case())


def test_message_secret_from_message_event_saved_to_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        storage = _DummyStorage()
        storage.creds = init_auth_creds()
        client = WAClient(storage, auto_ack_incoming=False)
        client.creds = storage.creds
        events: list[dict[str, Any]] = []

        async def _capture_event(event: dict[str, Any]) -> None:
            events.append(event)

        async def _fake_normalize(
            node: BinaryNode,
            signal_repo: object | None,
        ) -> dict[str, Any]:
            del node, signal_repo
            return {
                "type": "messages.upsert",
                "message": {
                    "id": "m-secret",
                    "from": "123@s.whatsapp.net",
                    "content_type": "poll_creation",
                    "message_secret_b64": base64.b64encode(b"\x42" * 32).decode("ascii"),
                },
            }

        monkeypatch.setattr("waton.client.client.normalize_incoming_node", _fake_normalize)
        client.on_event = _capture_event

        await client._handle_binary_node(
            BinaryNode(tag="message", attrs={"id": "m-secret", "from": "123@s.whatsapp.net"}, content=b"")
        )

        assert storage.creds.additional_data is not None
        secrets = storage.creds.additional_data["message_secrets"]
        assert secrets["m-secret"] == base64.b64encode(b"\x42" * 32).decode("ascii")
        assert events and events[0]["message_secret_saved"] == "m-secret"

    _run(_case())


def test_handle_success_sends_active_passive_iq_and_unified_session() -> None:
    async def _case() -> None:
        storage = _DummyStorage()
        storage.creds = init_auth_creds()
        storage.creds.me = {"id": "628123456789:1@s.whatsapp.net"}
        storage.creds.registered = True

        client = WAClient(storage)
        client.creds = storage.creds

        events: list[Any] = []
        sent_nodes: list[BinaryNode] = []

        async def _capture_event(event: Any) -> None:
            events.append(event)

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        client.on_connection_update = _capture_event
        client.send_node = _capture_send  # type: ignore[method-assign]
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())

        await client._handle_success(BinaryNode(tag="success", attrs={"lid": "226822071566383:67@lid"}))

        passive_nodes = [
            n
            for n in sent_nodes
            if n.tag == "iq" and n.attrs.get("xmlns") == "passive" and n.attrs.get("type") == "set"
        ]
        assert passive_nodes
        assert isinstance(passive_nodes[0].content, list)
        assert passive_nodes[0].content[0].tag == "active"

        unified_nodes = [n for n in sent_nodes if n.tag == "ib"]
        assert unified_nodes
        assert isinstance(unified_nodes[0].content, list)
        assert unified_nodes[0].content[0].tag == "unified_session"
        assert unified_nodes[0].content[0].attrs.get("id")

        assert events and events[-1].status == "open"

    _run(_case())


def test_handle_binary_node_offline_preview_requests_offline_batch() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        sent_nodes: list[BinaryNode] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())

        await client._handle_binary_node(
            BinaryNode(
                tag="ib",
                attrs={"from": "s.whatsapp.net"},
                content=[BinaryNode(tag="offline_preview", attrs={"count": "50"})],
            )
        )

        offline_batch_nodes = [
            n
            for n in sent_nodes
            if n.tag == "ib"
            and isinstance(n.content, list)
            and n.content
            and n.content[0].tag == "offline_batch"
        ]
        assert offline_batch_nodes
        assert offline_batch_nodes[0].content[0].attrs.get("count") == "100"

    _run(_case())


def test_offline_preview_ignores_non_whatsapp_source() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        sent_nodes: list[BinaryNode] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())

        await client._handle_binary_node(
            BinaryNode(
                tag="ib",
                attrs={"from": "not-whatsapp.net"},
                content=[BinaryNode(tag="offline_preview", attrs={"count": "50"})],
            )
        )

        offline_batch_nodes = [
            n
            for n in sent_nodes
            if n.tag == "ib"
            and isinstance(n.content, list)
            and n.content
            and n.content[0].tag == "offline_batch"
        ]
        assert offline_batch_nodes == []

    _run(_case())


def test_offline_preview_requests_offline_batch_only_once() -> None:
    async def _case() -> None:
        client = WAClient(_DummyStorage())
        sent_nodes: list[BinaryNode] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        client.send_node = _capture_send  # type: ignore[method-assign]
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())

        preview_node = BinaryNode(
            tag="ib",
            attrs={"from": "s.whatsapp.net"},
            content=[BinaryNode(tag="offline_preview", attrs={"count": "50"})],
        )
        await client._handle_binary_node(preview_node)
        await client._handle_binary_node(preview_node)

        offline_batch_nodes = [
            n
            for n in sent_nodes
            if n.tag == "ib"
            and isinstance(n.content, list)
            and n.content
            and n.content[0].tag == "offline_batch"
        ]
        assert len(offline_batch_nodes) == 1

    _run(_case())


def test_unified_session_id_uses_server_time_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    client = WAClient(_DummyStorage())
    fixed_now_s = 2_000_000
    monkeypatch.setattr("waton.client.client.time.time", lambda: float(fixed_now_s))

    client._update_server_time_offset(BinaryNode(tag="iq", attrs={"t": "2000100"}))

    week_ms = 7 * 24 * 60 * 60 * 1000
    offset_ms = 3 * 24 * 60 * 60 * 1000
    expected = str(((2_000_100 * 1000) + offset_ms) % week_ms)
    assert client._get_unified_session_id() == expected


def test_handle_success_uses_server_time_for_unified_session_id(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _case() -> None:
        storage = _DummyStorage()
        storage.creds = init_auth_creds()
        storage.creds.me = {"id": "628123456789:1@s.whatsapp.net"}
        storage.creds.registered = True

        client = WAClient(storage)
        client.creds = storage.creds
        client.is_connected = True
        client.noise = NoiseHandler(generate_keypair())

        sent_nodes: list[BinaryNode] = []

        async def _capture_send(node: BinaryNode) -> None:
            sent_nodes.append(node)

        client.send_node = _capture_send  # type: ignore[method-assign]
        monkeypatch.setattr("waton.client.client.time.time", lambda: float(2_000_000))

        await client._handle_success(BinaryNode(tag="success", attrs={"lid": "226822071566383:67@lid", "t": "2000100"}))

        unified_nodes = [
            n
            for n in sent_nodes
            if n.tag == "ib"
            and isinstance(n.content, list)
            and n.content
            and n.content[0].tag == "unified_session"
        ]
        assert unified_nodes

        week_ms = 7 * 24 * 60 * 60 * 1000
        offset_ms = 3 * 24 * 60 * 60 * 1000
        expected_id = str(((2_000_100 * 1000) + offset_ms) % week_ms)
        assert unified_nodes[0].content[0].attrs.get("id") == expected_id

    _run(_case())
