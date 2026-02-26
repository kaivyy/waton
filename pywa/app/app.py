"""High-level pywa application framework."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from pywa.app import filters as filters_module
from pywa.app.context import Context
from pywa.app.middleware import MiddlewarePipeline
from pywa.app.router import Router
from pywa.client.chats import ChatsAPI
from pywa.client.client import WAClient
from pywa.client.groups import GroupsAPI
from pywa.client.media import MediaManager
from pywa.client.messages import MessagesAPI
from pywa.client.presence import PresenceAPI
from pywa.core.entities import Message
from pywa.infra.storage_sqlite import SQLiteStorage
from pywa.protocol.binary_node import BinaryNode
from pywa.utils.process_message import process_incoming_message


ReadyCallback = Callable[["App"], Awaitable[None] | None]


class App:
    """Decorator-based high-level wrapper around WAClient."""

    def __init__(self, storage_path: str = "pywa.db") -> None:
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

        self.client.on_message = self._dispatch_message

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

        parsed = process_incoming_message(node)
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
            if self._on_ready_cb is not None:
                result = self._on_ready_cb(self)
                if result is not None:
                    loop.run_until_complete(result)
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            loop.run_until_complete(self.client.ws.disconnect())
            loop.run_until_complete(self.storage.close())
