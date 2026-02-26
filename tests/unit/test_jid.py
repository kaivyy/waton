from pywa.core.jid import (
    Jid,
    jid_decode,
    jid_encode,
    jid_normalized_user,
    is_jid_group,
    is_jid_user,
    S_WHATSAPP_NET
)

def test_jid_decode_simple():
    jid = jid_decode("12345678@s.whatsapp.net")
    assert jid is not None
    assert jid.user == "12345678"
    assert jid.server == S_WHATSAPP_NET
    assert jid.device is None

def test_jid_decode_with_device():
    jid = jid_decode("12345678:4@s.whatsapp.net")
    assert jid is not None
    assert jid.user == "12345678"
    assert jid.server == S_WHATSAPP_NET
    assert jid.device == 4

def test_jid_decode_server_only():
    jid = jid_decode("s.whatsapp.net")
    assert jid is not None
    assert jid.user == ""
    assert jid.server == S_WHATSAPP_NET
    assert jid.device is None

def test_jid_encode_simple():
    assert jid_encode("12345", S_WHATSAPP_NET) == f"12345@{S_WHATSAPP_NET}"

def test_jid_encode_with_device():
    assert jid_encode("12345", S_WHATSAPP_NET, 2) == f"12345:2@{S_WHATSAPP_NET}"

def test_jid_normalized_user():
    assert jid_normalized_user("123:4@s.whatsapp.net") == "123@s.whatsapp.net"
    assert jid_normalized_user("456@s.whatsapp.net") == "456@s.whatsapp.net"

def test_jid_matchers():
    assert is_jid_user("123@s.whatsapp.net")
    assert not is_jid_user("123@g.us")
    assert is_jid_group("123-456@g.us")
    assert not is_jid_group("123@s.whatsapp.net")
