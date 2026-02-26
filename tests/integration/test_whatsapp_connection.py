import asyncio
import os

import pytest

from pywa.client.client import WAClient
from pywa.infra.storage_sqlite import SQLiteStorage


pytestmark = pytest.mark.skipif(
    os.getenv("PYWA_RUN_WHATSAPP_INTEGRATION") != "1",
    reason="Set PYWA_RUN_WHATSAPP_INTEGRATION=1 to run live WhatsApp connection test.",
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

