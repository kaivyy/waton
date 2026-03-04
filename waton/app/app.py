"""High-level waton application framework."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from waton.app import filters as filters_module
from waton.app.context import Context
from waton.app.middleware import MiddlewareFn, MiddlewarePipeline
from waton.app.router import DecoratorFn, Router
from waton.client.chats import ChatsAPI
from waton.client.client import WAClient
from waton.client.communities import CommunitiesAPI
from waton.client.groups import GroupsAPI
from waton.client.media import MediaManager
from waton.client.messages import MessagesAPI
from waton.client.newsletter import NewsletterAPI
from waton.client.presence import PresenceAPI
from waton.core.entities import Message
from waton.infra.storage_sqlite import SQLiteStorage
from waton.utils.process_message import process_incoming_message

if TYPE_CHECKING:
    from waton.app.filters import Filter
    from waton.core.events import ConnectionEvent
    from waton.protocol.binary_node import BinaryNode

ReadyCallback = Callable[["App"], Awaitable[None] | None]
logger = logging.getLogger(__name__)


class App:
    """Decorator-based high-level wrapper around WAClient."""

    def __init__(self, storage_path: str = "waton.db") -> None:
        self.storage = SQLiteStorage(storage_path)
        self.client = WAClient(self.storage)

        self.messages = MessagesAPI(self.client)
        self.chats = ChatsAPI(self.client)
        self.groups = GroupsAPI(self.client)
        self.communities = CommunitiesAPI(self.client)
        self.newsletter = NewsletterAPI(self.client)
        self.media = MediaManager()
        self.presence = PresenceAPI(self.client)

        self.router = Router()
        self.middleware = MiddlewarePipeline()
        self._on_ready_cb: ReadyCallback | None = None

        self._connected_event = asyncio.Event()

        self.client.on_message = self._dispatch_message
        self._original_on_connection: Callable[[ConnectionEvent], Awaitable[None]] | None = (
            self.client.on_connection_update
        )
        self.client.on_connection_update = self._handle_connection_update

    async def _handle_connection_update(self, event: ConnectionEvent) -> None:
        if event.qr:
            print("\n=== SCAN THIS QR CODE ===")
            try:
                import qrcode
                qr = qrcode.QRCode(border=1)
                qr.add_data(event.qr)
                qr.make(fit=True)
                qr.print_ascii(invert=True)
            except ImportError:
                print(event.qr)
                print("(Install 'qrcode' package to see a graphical QR in terminal)")
            print("==========================\n")

        if event.status == "open":
            self._connected_event.set()

        if self._original_on_connection:
            await self._original_on_connection(event)

    def on_ready(self, func: ReadyCallback) -> ReadyCallback:
        self._on_ready_cb = func
        return func

    def use(self, middleware: MiddlewareFn) -> None:
        self.middleware.add(middleware)

    def message(self, custom_filter: Filter | None = None) -> DecoratorFn:
        return self.router.message(custom_filter)

    def command(self, prefix: str) -> DecoratorFn:
        return self.message(custom_filter=filters_module.command(prefix))

    async def _dispatch_message(self, node: BinaryNode) -> None:
        if node.tag != "message":
            return

        trace_id = uuid.uuid4().hex
        ingress_message_id = node.attrs.get("id", "") if isinstance(node.attrs.get("id"), str) else ""
        ingress_from = node.attrs.get("from", "") if isinstance(node.attrs.get("from"), str) else ""
        logger.debug(
            "dispatch stage",
            extra={
                "stage": "dispatch_ingress",
                "trace_id": trace_id,
                "message_id": ingress_message_id,
                "from_jid": ingress_from,
                "node_tag": node.tag,
            },
        )

        canonical_message_id = ingress_message_id
        dispatch_status = "ok"
        try:
            parsed = await process_incoming_message(node, self.client)
            message = Message(
                id=parsed.id,
                from_jid=parsed.from_jid,
                participant=parsed.participant,
                text=parsed.text,
                media_url=parsed.media_url,
                reaction=parsed.reaction,
                reaction_target_id=parsed.reaction_target_id,
                destination_jid=parsed.destination_jid,
                protocol_type=parsed.protocol_type,
                protocol_code=parsed.protocol_code,
                target_message_id=parsed.target_message_id,
                edited_text=parsed.edited_text,
                ephemeral_expiration=parsed.ephemeral_expiration,
                history_sync_type=parsed.history_sync_type,
                app_state_key_ids=parsed.app_state_key_ids,
                encrypted_reaction=parsed.encrypted_reaction,
                poll_update=parsed.poll_update,
                event_response=parsed.event_response,
                content_type=parsed.content_type,
                content=parsed.content,
                message_secret_b64=parsed.message_secret_b64,
                raw_node=node,
                message_type=parsed.message_type,
            )
            if not canonical_message_id:
                canonical_message_id = message.id
            logger.debug(
                "dispatch stage",
                extra={
                    "stage": "dispatch_parse_success",
                    "trace_id": trace_id,
                    "message_id": canonical_message_id,
                    "from_jid": message.from_jid,
                    "node_tag": node.tag,
                },
            )
        except Exception as exc:  # pragma: no cover - defensive fallback
            participant = node.attrs.get("participant") if isinstance(node.attrs.get("participant"), str) else None
            fallback_from = node.attrs.get("from", "") if isinstance(node.attrs.get("from"), str) else ""
            fallback_message_id = node.attrs.get("id", "") if isinstance(node.attrs.get("id"), str) else ""
            if not canonical_message_id:
                canonical_message_id = fallback_message_id
            logger.warning(
                "failed to parse incoming message %s: %s",
                fallback_message_id,
                exc,
                extra={
                    "stage": "dispatch_parse_fallback",
                    "trace_id": trace_id,
                    "message_id": canonical_message_id,
                    "from_jid": fallback_from,
                    "node_tag": node.tag,
                },
            )
            message = Message(
                id=fallback_message_id,
                from_jid=fallback_from,
                participant=participant,
                raw_node=node,
                message_type=node.attrs.get("type", "unknown"),
            )
        ctx = Context(message=message, app=self, trace_id=trace_id, trace_message_id=canonical_message_id)

        try:
            await self.middleware.run(ctx, self.router.dispatch)
        except Exception:
            dispatch_status = "error"
            raise
        finally:
            if not canonical_message_id:
                canonical_message_id = message.id
            logger.debug(
                "dispatch stage",
                extra={
                    "stage": "dispatch_complete",
                    "dispatch_status": dispatch_status,
                    "trace_id": trace_id,
                    "message_id": canonical_message_id,
                    "from_jid": message.from_jid,
                    "node_tag": node.tag,
                },
            )

    def run(self) -> None:
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.client.connect())
            print("[Waton] Handshake complete. Waiting for login/auth...")
            loop.run_until_complete(self._connected_event.wait())
            print("[Waton] Client authenticated successfully.")
            if self._on_ready_cb is not None:
                result = self._on_ready_cb(self)
                if result is not None:
                    loop.run_until_complete(result)
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            loop.run_until_complete(self.client.disconnect())
            loop.run_until_complete(self.storage.close())
