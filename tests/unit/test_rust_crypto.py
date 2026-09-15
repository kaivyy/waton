from waton.utils.crypto import signal_session_decrypt_prekey, signal_session_decrypt_whisper


def test_rust_decrypt_missing():
    assert callable(signal_session_decrypt_prekey)
    assert callable(signal_session_decrypt_whisper)
