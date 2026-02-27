class EventPipeline:
    def __init__(self, save_fn, emit_fn):
        self._save_fn = save_fn
        self._emit_fn = emit_fn

    async def process(self, event: dict) -> None:
        await self._save_fn(event)
        await self._emit_fn(event)
