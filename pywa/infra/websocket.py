import asyncio
import websockets
from typing import Callable, Awaitable, Any
from websockets.protocol import State
from pywa.core.errors import ConnectionError

class WebSocketTransport:
    """Async WebSocket transport wrapper for WhatsApp Web."""
    
    def __init__(self, override_url: str | None = None):
        self.url = override_url or "wss://web.whatsapp.com/ws/chat"
        self._ws: Any | None = None
        self._recv_task: asyncio.Task | None = None
        self.on_message: Callable[[bytes], Awaitable[None]] | None = None
        self.on_disconnect: Callable[[Exception], Awaitable[None]] | None = None

    async def connect(self):
        """Connects to WhatsApp WebSocket."""
        try:
            self._ws = await websockets.connect(
                self.url,
                origin="https://web.whatsapp.com",
                subprotocols=[],
                ping_interval=None,  # Handled at WS level by WA ping/pongs manually often
            )
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.url}: {e}")

        # Start listening loop
        self._recv_task = asyncio.create_task(self._listen_loop())

    async def disconnect(self):
        """Cleanly disconnects."""
        if self._recv_task:
            self._recv_task.cancel()
        if self._ws:
            await self._ws.close()
            wait_closed = getattr(self._ws, "wait_closed", None)
            if callable(wait_closed):
                await wait_closed()
            self._ws = None

    async def send(self, data: bytes):
        """Sends data through WebSocket."""
        if not self._is_ws_open():
            raise ConnectionError("WebSocket is disconnected")
        await self._ws.send(data)

    def _is_ws_open(self) -> bool:
        ws = self._ws
        if ws is None:
            return False

        # websockets<=11 style API
        if hasattr(ws, "closed"):
            return not bool(getattr(ws, "closed"))

        # websockets>=12 style API
        state = getattr(ws, "state", None)
        if state is None:
            return False
        return state == State.OPEN or state == 1

    async def _listen_loop(self):
        """Background loop to receive messages and dispatch to handler."""
        try:
            while True:
                message = await self._ws.recv()
                if self.on_message:
                    # WhatsApp binary protocol expects bytes
                    if isinstance(message, str):
                        message = message.encode()
                    # Schedule handler execution concurrently so as not to block recv
                    asyncio.create_task(self.on_message(message))
        except websockets.exceptions.ConnectionClosed as e:
            if self.on_disconnect:
                await self.on_disconnect(e)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self.on_disconnect:
                await self.on_disconnect(e)
