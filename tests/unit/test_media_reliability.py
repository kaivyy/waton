import socket

import pytest

from waton.client.media import MediaManager, upload_with_retry


def test_upload_retries_and_verifies_checksum(monkeypatch) -> None:
    result = upload_with_retry(b"abc", max_attempts=3)
    assert result["attempts"] >= 1
    assert result["verified"] is True


def test_media_url_guard_rejects_non_https_scheme() -> None:
    with pytest.raises(ValueError):
        MediaManager._validated_endpoint("ftp://example.com/file")


def test_media_url_guard_rejects_loopback_host(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(ValueError):
        MediaManager._validated_endpoint("https://example.com/file")


def test_media_url_guard_allows_public_https_host(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )
    _, host, resolved_ip = MediaManager._validated_endpoint("https://example.com/file")
    assert host == "example.com"
    assert resolved_ip == "93.184.216.34"


def test_media_url_guard_blocks_ipv6_loopback(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0))],
    )
    with pytest.raises(ValueError):
        MediaManager._validated_endpoint("https://example.com/file")


def test_derive_media_keys_mapping() -> None:
    from waton.utils.media_utils import derive_media_keys

    key = b"\x03" * 32
    # sticker must expand with "WhatsApp Image Keys"
    keys_sticker = derive_media_keys(key, "sticker")
    keys_image = derive_media_keys(key, "image")
    assert keys_sticker["cipher_key"] == keys_image["cipher_key"]

    # ptv must expand with "WhatsApp Video Keys"
    keys_ptv = derive_media_keys(key, "ptv")
    keys_video = derive_media_keys(key, "video")
    assert keys_ptv["cipher_key"] == keys_video["cipher_key"]

    # ptt must expand with "WhatsApp Audio Keys"
    keys_ptt = derive_media_keys(key, "ptt")
    keys_audio = derive_media_keys(key, "audio")
    assert keys_ptt["cipher_key"] == keys_audio["cipher_key"]

