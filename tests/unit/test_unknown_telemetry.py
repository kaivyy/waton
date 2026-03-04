from tools.parity.unknown_telemetry import summarize_unknown_events


def test_summarize_unknown_events_counts_types() -> None:
    rows = [
        {"event_type": "unknown_x"},
        {"event_type": "unknown_x"},
        {"event_type": "unknown_y"},
    ]
    out = summarize_unknown_events(rows)
    assert out["unknown_x"] == 2
    assert out["unknown_y"] == 1


def test_summarize_unknown_events_ignores_non_unknown_types() -> None:
    rows = [
        {"event_type": "message"},
        {"event_type": "notification"},
        {"event_type": "unknown_z"},
        {},
    ]
    out = summarize_unknown_events(rows)
    assert out == {"unknown_z": 1}
