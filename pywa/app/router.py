"""Simple async router for context handlers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pywa.app.filters import Filter


HandlerFn = Callable[["Context"], Awaitable[None] | None]


@dataclass
class Route:
    filter_fn: Filter | None
    handler: HandlerFn


class Router:
    def __init__(self) -> None:
        self._routes: list[Route] = []

    def message(self, filter_fn: Filter | None = None):
        def decorator(func: HandlerFn) -> HandlerFn:
            self._routes.append(Route(filter_fn=filter_fn, handler=func))
            return func

        return decorator

    async def dispatch(self, ctx: "Context") -> None:
        for route in self._routes:
            if route.filter_fn is not None and not route.filter_fn(ctx):
                continue
            result = route.handler(ctx)
            if result is not None:
                await result

    @property
    def routes(self) -> list[Route]:
        return self._routes

