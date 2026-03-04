"""Middleware pipeline for app message handling."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from waton.app.context import Context


logger = logging.getLogger(__name__)


NextCallable = Callable[[], Awaitable[None]]
MiddlewareFn = Callable[["Context", NextCallable], Awaitable[None]]
HandlerFn = Callable[["Context"], Awaitable[None]]


class MiddlewarePipeline:
    def __init__(self) -> None:
        self._stack: list[MiddlewareFn] = []

    def add(self, middleware: MiddlewareFn) -> None:
        self._stack.append(middleware)

    async def run(self, ctx: Context, final_handler: HandlerFn) -> None:
        async def execute(index: int) -> None:
            if index >= len(self._stack):
                await final_handler(ctx)
                return

            mw = self._stack[index]
            message = ctx.message
            if not ctx.trace_message_id:
                ctx.trace_message_id = message.id
            logger.debug(
                "dispatch stage",
                extra={
                    "stage": "middleware_enter",
                    "trace_id": ctx.trace_id,
                    "message_id": ctx.trace_message_id,
                    "from_jid": message.from_jid,
                    "middleware_index": index,
                },
            )

            async def next_step() -> None:
                await execute(index + 1)

            try:
                await mw(ctx, next_step)
            finally:
                logger.debug(
                    "dispatch stage",
                    extra={
                        "stage": "middleware_exit",
                        "trace_id": ctx.trace_id,
                        "message_id": ctx.trace_message_id,
                        "from_jid": message.from_jid,
                        "middleware_index": index,
                    },
                )

        await execute(0)

