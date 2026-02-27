"""High-level waton application framework."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from waton.app import filters as filters_module
from waton.app.context import Context
from waton.app.middleware import MiddlewarePipeline
from waton.app.router import Router
from waton.client.chats import ChatsAPI
from waton.client.client import WAClient
from waton.client.groups import GroupsAPI
from waton.client.media import MediaManager
from waton.client.messages import MessagesAPI
from waton.client.presence import PresenceAPI
from waton.core.entities import Message
from waton.infra.storage_sqlite import SQLiteStorage
from waton.protocol.binary_node import BinaryNode
from waton.utils.process_message import process_incoming_message


ReadyCallback = Callable[["App"], Awaitable[None] | None]


class App:
    """Decorator-based high-level wrapper around WAClient."""

    def __init__(self, storage_path: str = "waton.db") -> None:
        self.storage = SQLiteStorage(storage_path)
        self.client = WAClient(self.storage)

        self.messages = MessagesAPI(self.client)
        self.chats = ChatsAPI(self.client)
        self.groups = GroupsAPI(self.client)
        self.media = MediaManager()
        self.presence = PresenceAPI(self.client)

        self.router = Router()
        self.middleware = MiddlewarePipeline()
        self._on_ready_cb: ReadyCallback | None = None

        self._connected_event = asyncio.Event()

        self.client.on_message = self._dispatch_message
        self._original_on_connection = self.client.on_connection_update
        self.client.on_connection_update = self._handle_connection_update

    async def _handle_connection_update(self, event) -> None:
        if event.qr:
            print("\n=== SCAN THIS QR CODE ===")
            try:
                import qrcode
                qr = qrcode.QRCode(border=1)
                qr.add_data(event.qr)
                qr.make(fit=True)
                qr.print_ascii(invert=True)
            except ImportError:
                print(event.qr)
                print("(Install 'qrcode' package to see a graphical QR in terminal)")
            print("==========================\n")
        
        if event.status == "open":
            self._connected_event.set()
            
        if self._original_on_connection:
            await self._original_on_connection(event)

    def on_ready(self, func: ReadyCallback) -> ReadyCallback:
        self._on_ready_cb = func
        return func

    def use(self, middleware) -> None:
        self.middleware.add(middleware)

    def message(self, custom_filter=None):
        return self.router.message(custom_filter)

    def command(self, prefix: str):
        return self.message(custom_filter=filters_module.command(prefix))

    async def _dispatch_message(self, node: BinaryNode) -> None:
        if node.tag != "message":
            return

        parsed = await process_incoming_message(node, self.client)
        message = Message(
            id=parsed.id,
            from_jid=parsed.from_jid,
            participant=parsed.participant,
            text=parsed.text,
            raw_node=node,
            message_type=parsed.message_type,
        )
        ctx = Context(message=message, app=self)

        await self.middleware.run(ctx, self.router.dispatch)

    def run(self) -> None:
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.client.connect())
            print("[Waton] Handshake complete. Waiting for login/auth...")
            loop.run_until_complete(self._connected_event.wait())
            print("[Waton] Client authenticated successfully.")
            if self._on_ready_cb is not None:
                result = self._on_ready_cb(self)
                if result is not None:
                    loop.run_until_complete(result)
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            loop.run_until_complete(self.client.disconnect())
            loop.run_until_complete(self.storage.close())
