from __future__ import annotations

import argparse
import os
import pathlib
from typing import Any, Protocol

from flask import Flask, jsonify, render_template, request

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
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "mode": "real", "connection": dashboard_runtime.connection_state()})

    @app.get("/api/connection")
    def connection():
        return jsonify(dashboard_runtime.connection_state())

    @app.get("/api/qr")
    def qr():
        state = dashboard_runtime.connection_state()
        return jsonify(
            {
                "status": state.get("status"),
                "qr": state.get("qr"),
                "qr_image_data_url": state.get("qr_image_data_url"),
            }
        )

    @app.get("/api/events")
    def events():
        return jsonify({"events": dashboard_runtime.list_events()})

    @app.get("/api/debug/summary")
    def debug_summary():
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
    def chats():
        return jsonify({"chats": dashboard_runtime.list_chats()})

    @app.get("/api/chats/<path:chat_jid>/messages")
    def chat_messages(chat_jid: str):
        messages = dashboard_runtime.list_messages(chat_jid)
        return jsonify({"chat_jid": chat_jid, "messages": messages})

    @app.post("/api/chats/<path:chat_jid>/read")
    def mark_chat_read(chat_jid: str):
        dashboard_runtime.mark_chat_read(chat_jid)
        return jsonify({"status": "ok", "chat_jid": chat_jid})

    @app.post("/api/connect")
    def connect():
        try:
            state = dashboard_runtime.ensure_connected()
        except Exception as exc:
            return jsonify({"error": f"Failed to start WhatsApp connection: {exc}"}), 500
        return jsonify(state)

    @app.post("/api/disconnect")
    def disconnect():
        try:
            state = dashboard_runtime.disconnect()
        except Exception as exc:
            return jsonify({"error": f"Failed to disconnect: {exc}"}), 500
        return jsonify(state)

    @app.post("/api/send")
    def send():
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
