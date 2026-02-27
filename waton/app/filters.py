from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from waton.app.context import Context


class Filter:
    def __init__(self, fn: Callable[["Context"], bool]) -> None:
        self.fn = fn

    def __call__(self, ctx: "Context") -> bool:
        return self.fn(ctx)

    def __and__(self, other: "Filter") -> "Filter":
        return Filter(lambda ctx: self(ctx) and other(ctx))

    def __or__(self, other: "Filter") -> "Filter":
        return Filter(lambda ctx: self(ctx) or other(ctx))


def _make(fn: Callable[["Context"], bool]) -> Filter:
    return Filter(fn)


text = _make(lambda ctx: bool(ctx.text))
private = _make(lambda ctx: "@s.whatsapp.net" in ctx.from_jid)
group = _make(lambda ctx: "@g.us" in ctx.from_jid)


def regex(pattern: str) -> Filter:
    compiled = re.compile(pattern)
    return _make(lambda ctx: bool(ctx.text and compiled.search(ctx.text)))


def command(prefix: str) -> Filter:
    return _make(lambda ctx: bool(ctx.text and ctx.text.startswith(prefix)))
