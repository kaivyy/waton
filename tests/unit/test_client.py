import asyncio
from typing import Any

from waton.client.client import WAClient
from waton.core.errors import ConnectionError as WatonConnectionError
from waton.protocol.binary_node import BinaryNode
from waton.protocol.noise_handler import NoiseHandler
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
