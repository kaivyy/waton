from __future__ import annotations

from types import SimpleNamespace

import pytest

from waton.protocol.binary_node import BinaryNode
from waton.utils.live_probe import LiveProbe


@pytest.mark.asyncio
async def test_live_probe_wait_open_and_close() -> None:
    probe = LiveProbe()
    await probe.handle_connection_update(SimpleNamespace(status="connecting"))
    await probe.handle_connection_update(SimpleNamespace(status="open"))
    await probe.wait_open(timeout=0.1)
    await probe.handle_connection_update(SimpleNamespace(status="close"))
    await probe.wait_close(timeout=0.1)


@pytest.mark.asyncio
async def test_live_probe_ack_from_raw_ack_node() -> None:
    probe = LiveProbe()
    await probe.handle_message_node(
        BinaryNode(
            tag="ack",
            attrs={
                "class": "message",
                "id": "m-1",
                "from": "123@s.whatsapp.net",
            },
        )
    )
    ack = await probe.wait_for_message_ack("m-1", timeout=0.1)
    assert ack.status == "ok"
    assert ack.error is None
    assert ack.remote_jid == "123@s.whatsapp.net"


@pytest.mark.asyncio
async def test_live_probe_ack_from_bad_ack_event() -> None:
    probe = LiveProbe()
    await probe.handle_event(
        {
            "type": "messages.bad_ack",
            "bad_ack": {
                "message_id": "m-2",
                "remote_jid": "999@s.whatsapp.net",
                "error": "479",
            },
        }
    )
    ack = await probe.wait_for_message_ack("m-2", timeout=0.1)
    assert ack.status == "error"
    assert ack.error == "479"
    assert ack.remote_jid == "999@s.whatsapp.net"


@pytest.mark.asyncio
async def test_live_probe_wait_for_message_ack_timeout() -> None:
    probe = LiveProbe()
    with pytest.raises(TimeoutError):
        await probe.wait_for_message_ack("missing-id", timeout=0.05)
