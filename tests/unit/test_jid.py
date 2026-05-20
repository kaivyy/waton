from waton import core
from waton.core.jid import (
    S_WHATSAPP_NET,
    is_hosted_lid_user,
    is_hosted_pn_user,
    is_jid_bot,
    is_jid_group,
    is_jid_meta_ai,
    is_jid_newsletter,
    is_jid_status_broadcast,
    is_jid_user,
    is_lid_user,
    jid_decode,
    jid_encode,
    jid_normalized_user,
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


def test_jid_decode_agent_and_device():
    jid = jid_decode("12345_128:4@hosted")
    assert jid is not None
    assert jid.user == "12345"
    assert jid.agent == 128
    assert jid.device == 4
    assert jid.server == "hosted"


def test_jid_decode_preserves_non_numeric_underscore_user():
    jid = jid_decode("user_alias:4@s.whatsapp.net")
    assert jid is not None
    assert jid.user == "user_alias"
    assert jid.agent is None
    assert jid.device == 4


def test_jid_encode_agent_and_device():
    assert jid_encode("12345", "hosted", device=4, agent=128) == "12345_128:4@hosted"


def test_baileys_v7_jid_matchers():
    assert is_lid_user("123@lid")
    assert is_hosted_pn_user("123@hosted")
    assert is_hosted_lid_user("123@hosted.lid")
    assert is_jid_newsletter("123@newsletter")
    assert is_jid_status_broadcast("status@broadcast")
    assert is_jid_meta_ai("13135550002@bot")
    assert is_jid_bot("13135551234@c.us")
    assert not is_jid_bot("123@s.whatsapp.net")


def test_baileys_v7_jid_helpers_are_core_exports():
    assert core.is_hosted_pn_user("123@hosted")
    assert core.is_hosted_lid_user("123@hosted.lid")
    assert core.is_jid_newsletter("123@newsletter")
    assert core.is_jid_status_broadcast("status@broadcast")
