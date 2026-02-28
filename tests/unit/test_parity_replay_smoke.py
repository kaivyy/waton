from pathlib import Path

from tools.parity.replay_smoke import replay_fixture


def test_replay_fixture_returns_normalized_event() -> None:
    fixture_path = (
        Path(__file__).resolve().parent.parent
        / "fixtures"
        / "parity"
        / "smoke"
        / "message-basic.json"
    )

    out = replay_fixture(fixture_path)
    assert out["event_type"] == "message"
    assert out["normalized"] is True
