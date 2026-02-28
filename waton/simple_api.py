"""Simple callback-style API surface for quick bot usage."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

from waton.app.app import App
from waton.app.context import Context


class SimpleIncomingMessage:
    """Ergonomic incoming message wrapper for simple API handlers."""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx
        self._message = ctx.message

    @property
    def id(self) -> str:
        return self._message.id

    @property
    def text(self) -> str | None:
        return self._message.text

    @property
    def from_jid(self) -> str:
        return self._message.from_jid

    @property
    def sender(self) -> str:
        return self._message.participant or self._message.from_jid

    async def reply(self, text: str) -> str:
        return await self._ctx.reply(text)

    async def react(self, emoji: str) -> str:
        return await self._ctx.react(emoji)


class SimpleClient:
    """Minimal callback-based wrapper around :class:`waton.app.app.App`."""

    def __init__(self, storage_path: str = "waton.db") -> None:
        self.app = App(storage_path=storage_path)

    @staticmethod
    def _ensure_async_handler(handler: Callable[..., Awaitable[None]], name: str) -> None:
        if not inspect.iscoroutinefunction(handler):
            raise TypeError(f"{name} handler must be an async function")

    def on_message(
        self,
        handler: Callable[[SimpleIncomingMessage], Awaitable[None]],
    ) -> Callable[[SimpleIncomingMessage], Awaitable[None]]:
        self._ensure_async_handler(handler, "on_message")

        @self.app.message()
        async def _dispatch(ctx: Context) -> None:
            await handler(SimpleIncomingMessage(ctx))

        return handler

    def on_ready(
        self,
        handler: Callable[["SimpleClient"], Awaitable[None]],
    ) -> Callable[["SimpleClient"], Awaitable[None]]:
        self._ensure_async_handler(handler, "on_ready")

        @self.app.on_ready
        async def _dispatch(_: App) -> None:
            await handler(self)

        return handler

    async def send_text(self, to_jid: str, text: str) -> str:
        if not isinstance(to_jid, str) or not to_jid.strip():
            raise ValueError("to_jid must be a non-empty string")
        return await self.app.messages.send_text(to_jid.strip(), text)

    def run(self) -> None:
        self.app.run()


def simple(storage_path: str = "waton.db") -> SimpleClient:
    """Create a minimal callback-based Waton client."""

    return SimpleClient(storage_path=storage_path)
