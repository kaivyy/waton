from types import SimpleNamespace

from pywa.app import filters


def _ctx(text: str | None, from_jid: str):
    return SimpleNamespace(text=text, from_jid=from_jid)


def test_basic_filters() -> None:
    assert filters.text(_ctx("hi", "1@s.whatsapp.net"))
    assert not filters.text(_ctx("", "1@s.whatsapp.net"))
    assert filters.private(_ctx("x", "1@s.whatsapp.net"))
    assert filters.group(_ctx("x", "1-2@g.us"))


def test_regex_and_command_filters() -> None:
    assert filters.regex(r"^hello")(_ctx("hello world", "1@s.whatsapp.net"))
    assert not filters.regex(r"^hello")(_ctx("bye", "1@s.whatsapp.net"))
    assert filters.command("!ping")(_ctx("!ping now", "1@s.whatsapp.net"))
    assert not filters.command("!ping")(_ctx("!pong", "1@s.whatsapp.net"))


def test_filter_composition() -> None:
    composed = filters.text & filters.private
    assert composed(_ctx("ok", "1@s.whatsapp.net"))
    assert not composed(_ctx("ok", "1-2@g.us"))
