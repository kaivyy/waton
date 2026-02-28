from tools.parity.replay_smoke import replay_fixture


def test_replay_fixture_returns_normalized_event() -> None:
    out = replay_fixture("tests/fixtures/parity/smoke/message-basic.json")
    assert "event_type" in out
