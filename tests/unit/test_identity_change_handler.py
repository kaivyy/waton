from waton.client.identity_change_handler import handle_identity_change

def test_identity_change_marks_session_stale() -> None:
    state = {"session_stale": False}
    out = handle_identity_change(state, jid="123@s.whatsapp.net")
    assert out["session_stale"] is True
