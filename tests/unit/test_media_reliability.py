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
