import asyncio

import pytest
from websockets.protocol import State

from waton.core.errors import ConnectionError as WatonConnectionError
from waton.infra.websocket import WebSocketTransport


class _LegacyWs:
    def __init__(self, closed: bool) -> None:
        self.closed = closed
        self.sent: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)


class _StateWs:
    def __init__(self, state: State) -> None:
        self.state = state
        self.sent: list[bytes] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(data)


def _run(coro):
    return asyncio.run(coro)


def test_send_with_legacy_open_socket() -> None:
    transport = WebSocketTransport()
    ws = _LegacyWs(closed=False)
    transport._ws = ws

    _run(transport.send(b"abc"))

    assert ws.sent == [b"abc"]


def test_send_with_state_based_open_socket() -> None:
    transport = WebSocketTransport()
    ws = _StateWs(state=State.OPEN)
    transport._ws = ws

    _run(transport.send(b"xyz"))

    assert ws.sent == [b"xyz"]


def test_send_raises_when_state_based_socket_closed() -> None:
    transport = WebSocketTransport()
    transport._ws = _StateWs(state=State.CLOSED)

    with pytest.raises(WatonConnectionError):
        _run(transport.send(b"x"))


class _DisconnectWs:
    def __init__(self) -> None:
        self.close_called = False
        self.wait_closed_called = False

    async def close(self) -> None:
        self.close_called = True

    async def wait_closed(self) -> None:
        self.wait_closed_called = True


def test_disconnect_emits_on_disconnect_callback() -> None:
    async def _case() -> None:
        transport = WebSocketTransport()
        ws = _DisconnectWs()
        transport._ws = ws
        transport._recv_task = asyncio.create_task(asyncio.sleep(10))

        seen: list[Exception] = []

        async def _capture(exc: Exception) -> None:
            seen.append(exc)

        transport.on_disconnect = _capture
        await transport.disconnect()

        assert ws.close_called is True
        assert ws.wait_closed_called is True
        assert transport._ws is None
        assert len(seen) == 1

    _run(_case())

