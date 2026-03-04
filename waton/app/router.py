"""Simple async router for context handlers."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from waton.app.context import Context
    from waton.app.filters import Filter


logger = logging.getLogger(__name__)


HandlerFn = Callable[["Context"], Awaitable[None] | None]
DecoratorFn = Callable[[HandlerFn], HandlerFn]


@dataclass
class Route:
    filter_fn: Filter | None
    handler: HandlerFn


class Router:
    def __init__(self) -> None:
        self._routes: list[Route] = []

    def message(self, filter_fn: Filter | None = None) -> DecoratorFn:
        def decorator(func: HandlerFn) -> HandlerFn:
            self._routes.append(Route(filter_fn=filter_fn, handler=func))
            return func

        return decorator

    async def dispatch(self, ctx: Context) -> None:
        message = ctx.message
        if not ctx.trace_message_id:
            ctx.trace_message_id = message.id
        for index, route in enumerate(self._routes):
            matched = route.filter_fn is None or route.filter_fn(ctx)
            logger.debug(
                "dispatch stage",
                extra={
                    "stage": "route_match" if matched else "route_skip",
                    "trace_id": ctx.trace_id,
                    "message_id": ctx.trace_message_id,
                    "from_jid": message.from_jid,
                    "route_index": index,
                },
            )
            if not matched:
                continue
            result = route.handler(ctx)
            if result is not None:
                await result

    @property
    def routes(self) -> list[Route]:
        return self._routes

