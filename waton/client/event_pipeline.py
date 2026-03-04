from collections.abc import Awaitable, Callable, Mapping


class EventPipeline:
    def __init__(
        self,
        save_fn: Callable[[Mapping[str, object]], Awaitable[None]],
        emit_fn: Callable[[Mapping[str, object]], Awaitable[None]],
    ) -> None:
        self._save_fn = save_fn
        self._emit_fn = emit_fn

    async def process(self, event: Mapping[str, object]) -> None:
        await self._save_fn(event)
        await self._emit_fn(event)
