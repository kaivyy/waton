import asyncio

import pytest
from websockets.protocol import State

from waton.core.errors import ConnectionError
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

    with pytest.raises(ConnectionError):
        _run(transport.send(b"x"))

