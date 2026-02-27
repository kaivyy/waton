import asyncio
import os

import pytest

from waton.client.client import WAClient
from waton.infra.storage_sqlite import SQLiteStorage


pytestmark = pytest.mark.skipif(
    os.getenv("WATON_RUN_WHATSAPP_INTEGRATION") != "1",
    reason="Set WATON_RUN_WHATSAPP_INTEGRATION=1 to run live WhatsApp connection test.",
)


def test_whatsapp_transport_connection() -> None:
    async def _run() -> None:
        storage = SQLiteStorage(":memory:")
        client = WAClient(storage)

        try:
            await client.connect()
            assert client.is_transport_connected is True
        finally:
            await client.ws.disconnect()
            await storage.close()

    asyncio.run(_run())

