import pytest
from pywa.utils.crypto import signal_session_decrypt_prekey, signal_session_decrypt_whisper

def test_rust_decrypt_missing():
    # Verify the functions are callable (will fail until implemented in rust/src/lib.rs)
    assert callable(signal_session_decrypt_prekey)
    assert callable(signal_session_decrypt_whisper)
