from __future__ import annotations

import os

import pytest

from waton.utils.live_check import LiveCheckConfig, run_live_check


@pytest.mark.skipif(
    os.getenv("WATON_RUN_LIVE_RELIABILITY") != "1",
    reason="Set WATON_RUN_LIVE_RELIABILITY=1 to run live reliability tests.",
)
@pytest.mark.asyncio
async def test_live_send_receive_reconnect_cycle() -> None:
    config = LiveCheckConfig(
        auth_db=os.getenv("WATON_AUTH_DB", "waton_live.db"),
        test_jid=os.getenv("WATON_TEST_JID"),
        test_text=os.getenv("WATON_TEST_TEXT", "waton live reliability probe"),
        timeout_s=float(os.getenv("WATON_LIVE_TIMEOUT", "90")),
        close_timeout_s=float(os.getenv("WATON_LIVE_CLOSE_TIMEOUT", "30")),
        ack_timeout_s=float(os.getenv("WATON_ACK_TIMEOUT", os.getenv("WATON_LIVE_TIMEOUT", "45"))),
        reconnect_delay_s=float(os.getenv("WATON_LIVE_RECONNECT_DELAY", "1.5")),
        require_reconnect=os.getenv("WATON_LIVE_RECONNECT", "1") not in {"0", "false", "False"},
    )
    report = await run_live_check(config)
    assert report.open_ok is True
    assert report.ping_ok is True
    if config.test_jid:
        assert report.send_attempted is True
        assert report.send_ack is not None
        assert report.send_ack.status == "ok"
    if config.require_reconnect:
        assert report.close_ok is True
        assert report.reconnect_open_ok is True
        assert report.reconnect_ping_ok is True
