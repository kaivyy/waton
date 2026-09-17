from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping


class EventPipeline:
    def __init__(
        self,
        save_fn: Callable[[Mapping[str, object]], Awaitable[None]],
        emit_fn: Callable[[Mapping[str, object]], Awaitable[None]],
        *,
        batch_size: int = 10,
    ) -> None:
        self._save_fn = save_fn
        self._emit_fn = emit_fn
        self.batch_size = max(1, int(batch_size))
        self._queue: list[Mapping[str, object]] = []
        self._processed_in_batch: int = 0
        self._lock = asyncio.Lock()

    async def process(self, event: Mapping[str, object]) -> None:
        await self._save_fn(event)
        await self._emit_fn(event)
        self._processed_in_batch += 1
        if self._processed_in_batch >= self.batch_size:
            self._processed_in_batch = 0
            await asyncio.sleep(0)

    def enqueue(self, event: Mapping[str, object]) -> None:
        self._queue.append(event)

    async def flush(self) -> int:
        async with self._lock:
            count = 0
            while self._queue:
                event = self._queue[0]
                try:
                    await self.process(event)
                finally:
                    if self._queue and self._queue[0] is event:
                        self._queue.pop(0)
                count += 1
            return count


