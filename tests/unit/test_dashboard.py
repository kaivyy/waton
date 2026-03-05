import io

import pytest

from tools.dashboard.runtime import (
    DashboardRuntime,
    build_media_descriptor,
    choose_lid_chat_fallback,
    compute_route_keys,
    extract_alt_pn_from_attrs,
    extract_peer_jid_from_attrs,
    normalize_jid_for_chat,
    should_schedule_auto_reconnect,
)
from tools.dashboard.server import create_app
from tools.dashboard.state import DashboardEvent, DashboardState, normalize_wa_id
from waton.core.errors import ConnectionError as WatonConnectionError


def test_normalize_wa_id_accepts_plain_plus_and_jid():
    assert normalize_wa_id("6281234567890") == "6281234567890"
    assert normalize_wa_id("+6281234567890") == "6281234567890"
    assert normalize_wa_id("6281234567890@s.whatsapp.net") == "6281234567890"


def test_normalize_wa_id_rejects_invalid_value():
    with pytest.raises(ValueError):
        normalize_wa_id("abc123")
    with pytest.raises(ValueError):
        normalize_wa_id("62-81234")


def test_normalize_jid_for_chat_removes_device_suffix():
    assert normalize_jid_for_chat("6281234567890:26@s.whatsapp.net") == "6281234567890@s.whatsapp.net"


def test_normalize_jid_for_chat_maps_hosted_servers():
    assert normalize_jid_for_chat("6281234567890@hosted") == "6281234567890@s.whatsapp.net"
    assert normalize_jid_for_chat("179981124669483:0@hosted.lid") == "179981124669483@lid"


def test_extract_alt_pn_from_attrs_prefers_phone_number_jid():
    attrs = {
        "participant_pn": "6287000000001@s.whatsapp.net",
        "participant_lid": "179981124669483:0@lid",
    }
    assert extract_alt_pn_from_attrs(attrs) == "6287000000001@s.whatsapp.net"


def test_extract_alt_pn_from_attrs_accepts_recipient_pn():
    attrs = {
        "from": "179981124669483:0@lid",
        "recipient_pn": "6287000000001@s.whatsapp.net",
    }
    assert extract_alt_pn_from_attrs(attrs) == "6287000000001@s.whatsapp.net"


def test_extract_peer_jid_from_attrs_prefers_pn_and_skips_self():
    me_jids = {"6287000000002@s.whatsapp.net", "226822071566383@lid"}
    attrs = {
        "from": "6287000000002:64@s.whatsapp.net",
        "participant_lid": "179981124669483:0@lid",
        "participant_pn": "6287000000001@s.whatsapp.net",
    }
    assert extract_peer_jid_from_attrs(attrs, me_jids) == "6287000000001@s.whatsapp.net"


def test_extract_peer_jid_from_attrs_falls_back_to_lid():
    me_jids = {"6287000000002@s.whatsapp.net", "226822071566383@lid"}
    attrs = {
        "from": "6287000000002@s.whatsapp.net",
        "sender_lid": "179981124669483:0@hosted.lid",
    }
    assert extract_peer_jid_from_attrs(attrs, me_jids) == "179981124669483@lid"


def test_extract_peer_jid_from_attrs_accepts_recipient_pn():
    me_jids = {"6287000000002@s.whatsapp.net", "226822071566383@lid"}
    attrs = {
        "from": "6287000000002:64@s.whatsapp.net",
        "recipient_pn": "6287000000001@s.whatsapp.net",
        "recipient_lid": "179981124669483:0@lid",
    }
    assert extract_peer_jid_from_attrs(attrs, me_jids) == "6287000000001@s.whatsapp.net"


def test_compute_route_keys_for_direct_incoming():
    chat, sender, from_me = compute_route_keys(
        from_jid="6287000000001@s.whatsapp.net",
        participant_jid="",
        destination_jid="",
        me_jids={"6287000000002@s.whatsapp.net", "226822071566383@lid"},
    )
    assert chat == "6287000000001@s.whatsapp.net"
    assert sender == "6287000000001@s.whatsapp.net"
    assert from_me is False


def test_compute_route_keys_for_incoming_with_participant():
    chat, sender, from_me = compute_route_keys(
        from_jid="6287000000002@s.whatsapp.net",
        participant_jid="6287000000001@s.whatsapp.net",
        destination_jid="",
        me_jids={"6287000000002@s.whatsapp.net", "226822071566383@lid"},
    )
    assert chat == "6287000000001@s.whatsapp.net"
    assert sender == "6287000000001@s.whatsapp.net"
    assert from_me is False


def test_compute_route_keys_for_outgoing_message():
    chat, sender, from_me = compute_route_keys(
        from_jid="6287000000002@s.whatsapp.net",
        participant_jid="",
        destination_jid="6287000000001@s.whatsapp.net",
        me_jids={"6287000000002@s.whatsapp.net", "226822071566383@lid"},
    )
    assert chat == "6287000000001@s.whatsapp.net"
    assert sender == "6287000000002@s.whatsapp.net"
    assert from_me is True


def test_choose_lid_chat_fallback_prefers_existing_hint():
    fallback = choose_lid_chat_fallback(
        incoming_chat_jid="179981124669483@lid",
        from_me=False,
        active_chat_jid="6287000000001@s.whatsapp.net",
        known_pn_chats=["6287000000001@s.whatsapp.net"],
        existing_hint="6287000000001@s.whatsapp.net",
    )
    assert fallback == "6287000000001@s.whatsapp.net"


def test_choose_lid_chat_fallback_uses_active_chat_when_single_pn_chat():
    fallback = choose_lid_chat_fallback(
        incoming_chat_jid="179981124669483@lid",
        from_me=False,
        active_chat_jid="6287000000001@s.whatsapp.net",
        known_pn_chats=["6287000000001@s.whatsapp.net"],
        existing_hint=None,
    )
    assert fallback == "6287000000001@s.whatsapp.net"


def test_choose_lid_chat_fallback_returns_none_when_multiple_pn_chats():
    fallback = choose_lid_chat_fallback(
        incoming_chat_jid="179981124669483@lid",
        from_me=False,
        active_chat_jid="6287000000001@s.whatsapp.net",
        known_pn_chats=["6287000000001@s.whatsapp.net", "628111111111@s.whatsapp.net"],
        existing_hint=None,
    )
    assert fallback is None


def test_persist_media_blob_rejects_path_traversal(monkeypatch, tmp_path):
    monkeypatch.setenv("WATON_DASHBOARD_MEDIA_CACHE_DIR", str(tmp_path))
    runtime = DashboardRuntime(auth_db_path=str(tmp_path / "test.db"))
    try:
        with pytest.raises(ValueError):
            runtime._persist_media_blob("../evil", b"x", mimetype="image/png", file_name="a.png")
        with pytest.raises(ValueError):
            runtime._persist_media_blob("..\\evil", b"x", mimetype="image/png", file_name="a.png")
        with pytest.raises(ValueError):
            runtime._persist_media_blob("a/b", b"x", mimetype="image/png", file_name="a.png")
    finally:
        runtime.close()


def test_persist_media_blob_writes_inside_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("WATON_DASHBOARD_MEDIA_CACHE_DIR", str(tmp_path))
    runtime = DashboardRuntime(auth_db_path=str(tmp_path / "test.db"))
    try:
        target = runtime._persist_media_blob("msg_123", b"hello", mimetype="image/png", file_name="x.png")
        assert target.exists()
        assert target.read_bytes() == b"hello"
        assert target.resolve().is_relative_to(tmp_path.resolve())
    finally:
        runtime.close()


def test_build_media_descriptor_for_image_content():
    media = build_media_descriptor(
        content_type="image",
        content={
            "url": "https://media.local/image",
            "mimetype": "image/jpeg",
            "caption": "hello image",
            "direct_path": "/v/t62.7118-24/abc",
            "media_key_b64": "a2V5",
        },
    )
    assert media is not None
    assert media["kind"] == "image"
    assert media["url"] == "https://media.local/image"
    assert media["mimetype"] == "image/jpeg"
    assert media["caption"] == "hello image"
    assert media["direct_path"] == "/v/t62.7118-24/abc"
    assert media["media_key_b64"] == "a2V5"


def test_build_media_descriptor_for_audio_content():
    media = build_media_descriptor(
        content_type="audio",
        content={
            "url": "https://media.local/audio",
            "mimetype": "audio/ogg; codecs=opus",
            "direct_path": "/v/t62.7118-24/def",
            "media_key_b64": "YXVkaW8ta2V5",
        },
    )
    assert media is not None
    assert media["kind"] == "audio"
    assert media["media_key_b64"] == "YXVkaW8ta2V5"


def test_build_media_descriptor_for_unknown_content_type_returns_none():
    media = build_media_descriptor(content_type="unknown", content={})
    assert media is None


def test_should_schedule_auto_reconnect_for_non_explicit_disconnect():
    assert should_schedule_auto_reconnect(reason=RuntimeError("socket dropped"), explicit_disconnect=False) is True


def test_should_schedule_auto_reconnect_blocks_logged_out_reason():
    assert should_schedule_auto_reconnect(reason=RuntimeError("logged out"), explicit_disconnect=False) is False


def test_should_schedule_auto_reconnect_blocks_status_401():
    assert (
        should_schedule_auto_reconnect(
            reason=RuntimeError("Connection Failure (401)"),
            explicit_disconnect=False,
        )
        is False
    )


def test_should_schedule_auto_reconnect_blocks_logged_out_status_code():
    reason = WatonConnectionError("Connection Failure", status_code=401)
    assert should_schedule_auto_reconnect(reason=reason, explicit_disconnect=False) is False


def test_should_schedule_auto_reconnect_allows_connection_lost_status_code():
    reason = WatonConnectionError("Connection was lost", status_code=408)
    assert should_schedule_auto_reconnect(reason=reason, explicit_disconnect=False) is True


def test_should_schedule_auto_reconnect_blocks_explicit_disconnect():
    assert should_schedule_auto_reconnect(reason=RuntimeError("socket dropped"), explicit_disconnect=True) is False


def test_dashboard_state_trims_old_events():
    state = DashboardState(max_events=2)
    state.add_event(DashboardEvent(kind="system", source="test", payload={"id": 1}))
    state.add_event(DashboardEvent(kind="system", source="test", payload={"id": 2}))
    state.add_event(DashboardEvent(kind="system", source="test", payload={"id": 3}))

    events = state.list_events()
    assert len(events) == 2
    assert events[0]["payload"]["id"] == 2
    assert events[1]["payload"]["id"] == 3


@pytest.fixture
def dashboard_client(monkeypatch):
    pytest.importorskip("flask")
    monkeypatch.setenv("WATON_DASHBOARD_API_TOKEN", "test-token")
    monkeypatch.delenv("WATON_DASHBOARD_ALLOW_REMOTE", raising=False)
    runtime = _FakeRuntime()
    app = create_app(testing=True, runtime=runtime)
    app.config["DASHBOARD_RUNTIME"] = runtime
    with app.test_client() as client:
        client.environ_base["HTTP_AUTHORIZATION"] = "Bearer test-token"
        client.environ_base["REMOTE_ADDR"] = "127.0.0.1"
        yield client


def test_dashboard_api_requires_bearer_token(monkeypatch):
    pytest.importorskip("flask")
    monkeypatch.setenv("WATON_DASHBOARD_API_TOKEN", "test-token")
    app = create_app(testing=True, runtime=_FakeRuntime())
    with app.test_client() as client:
        client.environ_base["REMOTE_ADDR"] = "127.0.0.1"
        res = client.get("/api/health")
    assert res.status_code == 401


def test_dashboard_api_rejects_non_loopback_by_default(monkeypatch):
    pytest.importorskip("flask")
    monkeypatch.setenv("WATON_DASHBOARD_API_TOKEN", "test-token")
    monkeypatch.delenv("WATON_DASHBOARD_ALLOW_REMOTE", raising=False)
    app = create_app(testing=True, runtime=_FakeRuntime())
    with app.test_client() as client:
        client.environ_base["REMOTE_ADDR"] = "10.10.10.10"
        res = client.get("/api/health", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 403


def test_dashboard_api_allows_remote_when_explicitly_enabled(monkeypatch):
    pytest.importorskip("flask")
    monkeypatch.setenv("WATON_DASHBOARD_API_TOKEN", "test-token")
    monkeypatch.setenv("WATON_DASHBOARD_ALLOW_REMOTE", "1")
    app = create_app(testing=True, runtime=_FakeRuntime())
    with app.test_client() as client:
        client.environ_base["REMOTE_ADDR"] = "10.10.10.10"
        res = client.get("/api/health", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200


def test_dashboard_health_endpoint(dashboard_client):
    res = dashboard_client.get("/api/health")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "ok"
    assert body["mode"] == "real"
    assert "connection" in body


def test_dashboard_connection_endpoint(dashboard_client):
    res = dashboard_client.get("/api/connection")
    assert res.status_code == 200
    body = res.get_json()
    assert body["state"] == "disconnected"
    assert body["status"] == "disconnected"


def test_dashboard_connect_endpoint(dashboard_client):
    runtime = dashboard_client.application.config["DASHBOARD_RUNTIME"]
    res = dashboard_client.post("/api/connect")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "connecting"
    assert runtime.ensure_connected_called is True


def test_dashboard_qr_endpoint(dashboard_client):
    dashboard_client.post("/api/connect")
    res = dashboard_client.get("/api/qr")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "connecting"
    assert body["qr"] == "qr,code,data"
    assert body["qr_image_data_url"].startswith("data:image/svg+xml;base64,")


def test_dashboard_disconnect_endpoint(dashboard_client):
    runtime = dashboard_client.application.config["DASHBOARD_RUNTIME"]
    res = dashboard_client.post("/api/disconnect")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "disconnected"
    assert runtime.disconnect_called is True


def test_dashboard_send_validation(dashboard_client):
    res = dashboard_client.post("/api/send", json={})
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_dashboard_events_endpoint(dashboard_client):
    res = dashboard_client.get("/api/events")
    assert res.status_code == 200
    body = res.get_json()
    assert "events" in body
    assert isinstance(body["events"], list)


def test_dashboard_debug_summary_endpoint(dashboard_client):
    res = dashboard_client.get("/api/debug/summary")
    assert res.status_code == 200
    body = res.get_json()
    assert "connection" in body
    assert body["chat_count"] == 1
    assert isinstance(body["chats"], list)
    assert isinstance(body["events_tail"], list)


def test_dashboard_chats_endpoint(dashboard_client):
    res = dashboard_client.get("/api/chats")
    assert res.status_code == 200
    body = res.get_json()
    assert "chats" in body
    assert isinstance(body["chats"], list)


def test_dashboard_chat_messages_endpoint(dashboard_client):
    res = dashboard_client.get("/api/chats/6281234567890%40s.whatsapp.net/messages")
    assert res.status_code == 200
    body = res.get_json()
    assert "chat_jid" in body
    assert "messages" in body
    assert isinstance(body["messages"], list)


def test_dashboard_mark_chat_read_endpoint(dashboard_client):
    res = dashboard_client.post("/api/chats/6281234567890%40s.whatsapp.net/read")
    assert res.status_code == 200
    body = res.get_json()
    assert body["chat_jid"] == "6281234567890@s.whatsapp.net"
    assert body["status"] == "ok"


def test_dashboard_send_success(dashboard_client):
    runtime = dashboard_client.application.config["DASHBOARD_RUNTIME"]
    runtime.state = {
        "state": "connected",
        "status": "connected",
        "qr": None,
        "qr_image_data_url": None,
        "reason": None,
        "me": {"id": "628111@s.whatsapp.net"},
    }
    res = dashboard_client.post("/api/send", json={"to": "6281234567890", "text": "hello"})
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "queued"
    assert body["to"] == "6281234567890@s.whatsapp.net"
    assert body["message_id"] == "msg123"
    assert runtime.last_send == ("6281234567890@s.whatsapp.net", "hello")


def test_dashboard_send_requires_connection(dashboard_client):
    res = dashboard_client.post("/api/send", json={"to": "6281234567890", "text": "hello"})
    assert res.status_code == 409
    assert "error" in res.get_json()


def test_dashboard_send_media_validation(dashboard_client):
    runtime = dashboard_client.application.config["DASHBOARD_RUNTIME"]
    runtime.state = {
        "state": "connected",
        "status": "connected",
        "qr": None,
        "qr_image_data_url": None,
        "reason": None,
        "me": {"id": "628111@s.whatsapp.net"},
    }
    res = dashboard_client.post("/api/send/media", data={"to": "6281234567890", "kind": "image"})
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_dashboard_send_media_success(dashboard_client):
    runtime = dashboard_client.application.config["DASHBOARD_RUNTIME"]
    runtime.state = {
        "state": "connected",
        "status": "connected",
        "qr": None,
        "qr_image_data_url": None,
        "reason": None,
        "me": {"id": "628111@s.whatsapp.net"},
    }
    res = dashboard_client.post(
        "/api/send/media",
        data={
            "to": "6281234567890",
            "kind": "document",
            "caption": "invoice",
            "file": (io.BytesIO(b"pdf-data"), "invoice.pdf", "application/pdf"),
        },
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "queued"
    assert body["to"] == "6281234567890@s.whatsapp.net"
    assert body["message_id"] == "media123"
    assert runtime.last_send_media is not None
    sent = runtime.last_send_media
    assert sent["to_jid"] == "6281234567890@s.whatsapp.net"
    assert sent["kind"] == "document"
    assert sent["caption"] == "invoice"
    assert sent["file_name"] == "invoice.pdf"
    assert sent["mimetype"] == "application/pdf"
    assert sent["media_bytes"] == b"pdf-data"


def test_dashboard_media_proxy_endpoint(dashboard_client):
    res = dashboard_client.get("/api/media/m1")
    assert res.status_code == 200
    assert res.mimetype == "image/webp"
    assert res.data == b"media-bytes"


def test_dashboard_send_media_sticker_requires_webp(dashboard_client):
    runtime = dashboard_client.application.config["DASHBOARD_RUNTIME"]
    runtime.state = {
        "state": "connected",
        "status": "connected",
        "qr": None,
        "qr_image_data_url": None,
        "reason": None,
        "me": {"id": "628111@s.whatsapp.net"},
    }
    res = dashboard_client.post(
        "/api/send/media",
        data={
            "to": "6281234567890",
            "kind": "sticker",
            "file": (io.BytesIO(b"png-data"), "sticker.png", "image/png"),
        },
    )
    assert res.status_code == 400
    assert "webp" in res.get_json()["error"].lower()


def test_dashboard_reconnect_endpoint(dashboard_client):
    runtime = dashboard_client.application.config["DASHBOARD_RUNTIME"]
    res = dashboard_client.post("/api/reconnect")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "connecting"
    assert runtime.ensure_connected_called is True


class _FakeRuntime:
    def __init__(self):
        self.events = []
        self.state = {
            "state": "disconnected",
            "status": "disconnected",
            "qr": None,
            "qr_image_data_url": None,
            "reason": None,
            "me": None,
        }
        self.ensure_connected_called = False
        self.disconnect_called = False
        self.last_send = None
        self.last_send_media = None

    def connection_state(self):
        return dict(self.state)

    def list_events(self):
        return list(self.events)

    def ensure_connected(self):
        self.ensure_connected_called = True
        self.state["state"] = "connecting"
        self.state["status"] = "connecting"
        self.state["qr"] = "qr,code,data"
        self.state["qr_image_data_url"] = "data:image/svg+xml;base64,abc"
        return dict(self.state)

    def disconnect(self):
        self.disconnect_called = True
        self.state["state"] = "disconnected"
        self.state["status"] = "disconnected"
        self.state["qr"] = None
        self.state["qr_image_data_url"] = None
        return dict(self.state)

    def send_text(self, to_jid: str, text: str):
        self.last_send = (to_jid, text)
        return "msg123"

    def send_media(
        self,
        *,
        to_jid: str,
        kind: str,
        media_bytes: bytes,
        file_name: str,
        mimetype: str,
        caption: str,
    ):
        self.last_send_media = {
            "to_jid": to_jid,
            "kind": kind,
            "media_bytes": media_bytes,
            "file_name": file_name,
            "mimetype": mimetype,
            "caption": caption,
        }
        return "media123"

    def get_media_blob(self, message_id: str):
        if message_id != "m1":
            return None
        return (b"media-bytes", "image/webp")

    def list_chats(self):
        return [
            {
                "jid": "6281234567890@s.whatsapp.net",
                "title": "6281234567890",
                "last_text": "hey",
                "last_timestamp": 1000,
                "unread_count": 1,
            }
        ]

    def list_messages(self, chat_jid: str):
        return [
            {
                "id": "m1",
                "chat_jid": chat_jid,
                "from_me": False,
                "sender_jid": chat_jid,
                "text": "hey",
                "timestamp": 1000,
                "status": "received",
            }
        ]

    def mark_chat_read(self, chat_jid: str):
        return None
