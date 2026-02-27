import pytest
from waton.client.event_pipeline import EventPipeline

@pytest.mark.asyncio
async def test_persist_happens_before_emit() -> None:
    calls = []
    async def mock_save(event):
        calls.append("save")
    async def mock_emit(event):
        calls.append("emit")
    pipeline = EventPipeline(save_fn=mock_save, emit_fn=mock_emit)
    await pipeline.process({"type": "messages.upsert"})
    assert calls == ["save", "emit"]
