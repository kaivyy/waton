from __future__ import annotations

from waton.defaults import DEFAULT_CONNECTION_CONFIG


def test_baileys_v7_power_flags_are_disabled_by_default() -> None:
    assert DEFAULT_CONNECTION_CONFIG["baileys_v7_reference"] == "7.0.0-rc11"
    assert DEFAULT_CONNECTION_CONFIG["baileys_v7_power_mode"] == "compatibility"
    assert DEFAULT_CONNECTION_CONFIG["enable_baileys_v7_shadow_decoders"] is False
    assert DEFAULT_CONNECTION_CONFIG["enable_baileys_v7_retry"] is False
    assert DEFAULT_CONNECTION_CONFIG["enable_baileys_v7_app_state_resilience"] is False
    assert DEFAULT_CONNECTION_CONFIG["enable_baileys_v7_send_diagnostics"] is False
