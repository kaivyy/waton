"""Middleware pipeline for app message handling."""

from __future__ import annotations

from collections.abc import Awaitable, Callable


NextCallable = Callable[[], Awaitable[None]]
MiddlewareFn = Callable[["Context", NextCallable], Awaitable[None]]
HandlerFn = Callable[["Context"], Awaitable[None]]


class MiddlewarePipeline:
    def __init__(self) -> None:
        self._stack: list[MiddlewareFn] = []

    def add(self, middleware: MiddlewareFn) -> None:
        self._stack.append(middleware)

    async def run(self, ctx: "Context", final_handler: HandlerFn) -> None:
        async def execute(index: int) -> None:
            if index >= len(self._stack):
                await final_handler(ctx)
                return

            mw = self._stack[index]

            async def next_step() -> None:
                await execute(index + 1)

            await mw(ctx, next_step)

        await execute(0)

