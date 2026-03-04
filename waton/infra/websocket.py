import asyncio
from typing import TYPE_CHECKING, Any, cast

import websockets
from websockets.protocol import State

from waton.core.errors import ConnectionError as WatonConnectionError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class WebSocketTransport:
    """Async WebSocket transport wrapper for WhatsApp Web."""

    def __init__(self, override_url: str | None = None) -> None:
        self.url = override_url or "wss://web.whatsapp.com/ws/chat"
        self._ws: Any | None = None
        self._recv_task: asyncio.Task[None] | None = None
        self.on_message: Callable[[bytes], Awaitable[None]] | None = None
        self.on_disconnect: Callable[[Exception], Awaitable[None]] | None = None

    async def connect(self) -> None:
        """Connects to WhatsApp WebSocket."""
        try:
            self._ws = await websockets.connect(
                self.url,
                origin=cast("Any", "https://web.whatsapp.com"),
                subprotocols=[],
                ping_interval=None,  # Handled at WS level by WA ping/pongs manually often
            )
        except Exception as e:
            raise WatonConnectionError(f"Failed to connect to {self.url}: {e}") from e

        # Start listening loop
        self._recv_task = asyncio.create_task(self._listen_loop())

    async def disconnect(self) -> None:
        """Cleanly disconnects."""
        if self._recv_task:
            self._recv_task.cancel()
        if self._ws:
            await self._ws.close()
            wait_closed = getattr(self._ws, "wait_closed", None)
            if callable(wait_closed):
                await cast("Awaitable[None]", wait_closed())
            self._ws = None
        if self.on_disconnect:
            await self.on_disconnect(WatonConnectionError("Disconnected by client"))

    async def send(self, data: bytes) -> None:
        """Sends data through WebSocket."""
        if not self._is_ws_open():
            raise WatonConnectionError("WebSocket is disconnected")
        ws = self._ws
        if ws is None:
            raise WatonConnectionError("WebSocket is disconnected")
        await ws.send(data)

    def _is_ws_open(self) -> bool:
        ws = self._ws
        if ws is None:
            return False

        # websockets<=11 style API
        if hasattr(ws, "closed"):
            return not bool(ws.closed)

        # websockets>=12 style API
        state = getattr(ws, "state", None)
        if state is None:
            return False
        return state == State.OPEN or state == 1

    async def _listen_loop(self) -> None:
        """Background loop to receive messages and dispatch to handler."""
        try:
            while True:
                ws = self._ws
                if ws is None:
                    break
                message = await ws.recv()
                if self.on_message:
                    # WhatsApp binary protocol expects bytes
                    payload = message.encode() if isinstance(message, str) else message
                    # Schedule handler execution concurrently so as not to block recv
                    asyncio.ensure_future(self.on_message(payload))
        except websockets.exceptions.ConnectionClosed as e:
            if self.on_disconnect:
                await self.on_disconnect(e)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self.on_disconnect:
                await self.on_disconnect(e)
