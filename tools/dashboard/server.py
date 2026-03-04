from __future__ import annotations

import argparse
import os
import pathlib
from typing import Any, Protocol

from flask import Flask, Response, jsonify, render_template, request

from .runtime import DashboardRuntime
from .state import normalize_wa_id


class DashboardRuntimeLike(Protocol):
    def connection_state(self) -> dict[str, Any]: ...

    def list_events(self) -> list[dict[str, Any]]: ...

    def list_chats(self) -> list[dict[str, Any]]: ...

    def list_messages(self, chat_jid: str) -> list[dict[str, Any]]: ...

    def mark_chat_read(self, chat_jid: str) -> None: ...

    def ensure_connected(self) -> dict[str, Any]: ...

    def disconnect(self) -> dict[str, Any]: ...

    def send_text(self, to_jid: str, text: str) -> str: ...

    def send_media(
        self,
        *,
        to_jid: str,
        kind: str,
        media_bytes: bytes,
        file_name: str,
        mimetype: str,
        caption: str,
    ) -> str: ...

    def get_media_blob(self, message_id: str) -> tuple[bytes, str] | None: ...


def _template_dir() -> str:
    return str(pathlib.Path(__file__).with_name("templates"))


def _static_dir() -> str:
    return str(pathlib.Path(__file__).with_name("static"))


def _build_send_payload(raw_to: str, text: str) -> tuple[str, str]:
    wa_id = normalize_wa_id(raw_to)
    return f"{wa_id}@s.whatsapp.net", text


def create_app(*, testing: bool = False, runtime: DashboardRuntimeLike | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder=_template_dir(),
        static_folder=_static_dir(),
        static_url_path="/static",
    )
    app.config["TESTING"] = testing
    auth_db_path = os.getenv("WATON_DASHBOARD_AUTH_DB", "waton_dashboard.db")
    dashboard_runtime = runtime or DashboardRuntime(auth_db_path=auth_db_path)
    app.config["DASHBOARD_RUNTIME"] = dashboard_runtime

    @app.get("/")
    def index() -> Any:
        return render_template("index.html")

    @app.get("/api/health")
    def health() -> Any:
        return jsonify({"status": "ok", "mode": "real", "connection": dashboard_runtime.connection_state()})

    @app.get("/api/connection")
    def connection() -> Any:
        return jsonify(dashboard_runtime.connection_state())

    @app.get("/api/qr")
    def qr() -> Any:
        state = dashboard_runtime.connection_state()
        return jsonify(
            {
                "status": state.get("status"),
                "qr": state.get("qr"),
                "qr_image_data_url": state.get("qr_image_data_url"),
            }
        )

    @app.get("/api/events")
    def events() -> Any:
        return jsonify({"events": dashboard_runtime.list_events()})

    @app.get("/api/debug/summary")
    def debug_summary() -> Any:
        events = dashboard_runtime.list_events()
        chats = dashboard_runtime.list_chats()
        return jsonify(
            {
                "connection": dashboard_runtime.connection_state(),
                "chat_count": len(chats),
                "chats": chats[:30],
                "events_tail": events[-40:],
            }
        )

    @app.get("/api/chats")
    def chats() -> Any:
        return jsonify({"chats": dashboard_runtime.list_chats()})

    @app.get("/api/chats/<path:chat_jid>/messages")
    def chat_messages(chat_jid: str) -> Any:
        messages = dashboard_runtime.list_messages(chat_jid)
        return jsonify({"chat_jid": chat_jid, "messages": messages})

    @app.post("/api/chats/<path:chat_jid>/read")
    def mark_chat_read(chat_jid: str) -> Any:
        dashboard_runtime.mark_chat_read(chat_jid)
        return jsonify({"status": "ok", "chat_jid": chat_jid})

    @app.post("/api/connect")
    def connect() -> Any:
        try:
            state = dashboard_runtime.ensure_connected()
        except Exception as exc:
            return jsonify({"error": f"Failed to start WhatsApp connection: {exc}"}), 500
        return jsonify(state)

    @app.post("/api/disconnect")
    def disconnect() -> Any:
        try:
            state = dashboard_runtime.disconnect()
        except Exception as exc:
            return jsonify({"error": f"Failed to disconnect: {exc}"}), 500
        return jsonify(state)

    @app.post("/api/reconnect")
    def reconnect() -> Any:
        try:
            state = dashboard_runtime.ensure_connected()
        except Exception as exc:
            return jsonify({"error": f"Failed to reconnect: {exc}"}), 500
        return jsonify(state)

    @app.post("/api/send")
    def send() -> Any:
        data = request.get_json(silent=True) or {}
        raw_to = (data.get("to") or "").strip()
        text = (data.get("text") or "").strip()
        if not raw_to or not text:
            return jsonify({"error": "`to` and `text` are required."}), 400

        state = dashboard_runtime.connection_state()
        if state.get("state") != "connected":
            return jsonify({"error": "WhatsApp is not connected. Scan QR first."}), 409

        try:
            to_jid, normalized_text = _build_send_payload(raw_to=raw_to, text=text)
            message_id = dashboard_runtime.send_text(to_jid=to_jid, text=normalized_text)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409
        except Exception as exc:
            return jsonify({"error": f"Send failed: {exc}"}), 500

        return jsonify({"status": "queued", "to": to_jid, "message_id": message_id})

    @app.post("/api/send/media")
    def send_media() -> Any:
        raw_to = (request.form.get("to") or "").strip()
        kind = (request.form.get("kind") or "").strip().lower()
        caption = (request.form.get("caption") or "").strip()
        upload = request.files.get("file")

        if not raw_to or not kind or upload is None:
            return jsonify({"error": "`to`, `kind`, and `file` are required."}), 400

        state = dashboard_runtime.connection_state()
        if state.get("state") != "connected":
            return jsonify({"error": "WhatsApp is not connected. Scan QR first."}), 409

        file_name = upload.filename or "upload.bin"
        mimetype = upload.mimetype or "application/octet-stream"
        media_bytes = upload.read()
        if not media_bytes:
            return jsonify({"error": "`file` must not be empty."}), 400
        if kind == "sticker" and not file_name.lower().endswith(".webp"):
            return jsonify({"error": "Sticker upload must use .webp file."}), 400

        try:
            to_jid, _ = _build_send_payload(raw_to=raw_to, text="x")
            message_id = dashboard_runtime.send_media(
                to_jid=to_jid,
                kind=kind,
                media_bytes=media_bytes,
                file_name=file_name,
                mimetype=mimetype,
                caption=caption,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 409
        except Exception as exc:
            return jsonify({"error": f"Send failed: {exc}"}), 500

        return jsonify({"status": "queued", "to": to_jid, "message_id": message_id})

    @app.get("/api/media/<message_id>")
    def media_blob(message_id: str) -> Any:
        blob = dashboard_runtime.get_media_blob(message_id)
        if blob is None:
            return jsonify({"error": "Media not found."}), 404
        data, mimetype = blob
        return Response(data, mimetype=mimetype)

    return app


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Waton browser dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
