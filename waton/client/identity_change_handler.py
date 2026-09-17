"""Handler for identity key changes in WhatsApp multi-device protocol."""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from waton.core.jid import jid_decode, jid_normalized_user
from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class IdentityChangeContext:
    me_id: str | None = None
    me_lid: str | None = None
    validate_session: Callable[[str], Awaitable[bool]] | None = None
    assert_sessions: Callable[[list[str], bool], Awaitable[bool]] | None = None
    on_before_session_refresh: Callable[[str], None] | None = None
    debounce_cache: dict[str, float] | None = None
    debounce_ttl_seconds: float = 10.0


async def handle_identity_change_node(
    node: BinaryNode,
    ctx: IdentityChangeContext,
) -> dict[str, Any]:
    """
    Process incoming `<notification type="encrypt"><identity>...</identity></notification>`.
    Mirrors Baileys `handleIdentityChange`.
    """
    from_jid = node.attrs.get("from")
    if not from_jid:
        return {"action": "invalid_notification"}

    # Check for <identity> child
    identity_node = None
    if isinstance(node.content, list):
        for child in node.content:
            if isinstance(child, BinaryNode) and child.tag == "identity":
                identity_node = child
                break

    if not identity_node:
        return {"action": "no_identity_node"}

    logger.info("identity changed for %s", from_jid)

    decoded = jid_decode(from_jid)
    if decoded and decoded.device is not None and decoded.device != 0:
        logger.debug("ignoring identity change from companion device: %s:%d", from_jid, decoded.device)
        return {"action": "skipped_companion_device", "device": decoded.device}

    # Check if from is self primary
    norm_from = jid_normalized_user(from_jid)
    if ctx.me_id and norm_from == jid_normalized_user(ctx.me_id):
        logger.info("self primary identity changed for %s", from_jid)
        return {"action": "skipped_self_primary"}
    if ctx.me_lid and norm_from == jid_normalized_user(ctx.me_lid):
        logger.info("self primary LID identity changed for %s", from_jid)
        return {"action": "skipped_self_primary"}

    # Debounce check
    now = time.time()
    cache = ctx.debounce_cache if ctx.debounce_cache is not None else {}
    last_seen = cache.get(from_jid, 0.0)
    if now - last_seen < ctx.debounce_ttl_seconds:
        logger.debug("skipping identity assert for %s (debounced)", from_jid)
        return {"action": "debounced"}

    cache[from_jid] = now

    is_offline = bool(node.attrs.get("offline"))

    has_existing = False
    if ctx.validate_session:
        has_existing = await ctx.validate_session(from_jid)

    if not has_existing:
        logger.debug("no old session for %s, skipping session refresh", from_jid)
        return {"action": "skipped_no_session"}

    if is_offline:
        logger.debug("skipping session refresh during offline processing for %s", from_jid)
        return {"action": "skipped_offline"}

    if ctx.on_before_session_refresh:
        try:
            ctx.on_before_session_refresh(from_jid)
        except Exception as exc:
            logger.warning("error in on_before_session_refresh for %s: %s", from_jid, exc)

    if ctx.assert_sessions:
        try:
            await ctx.assert_sessions([from_jid], True)
            return {"action": "session_refreshed"}
        except Exception as exc:
            logger.warning("failed to assert sessions after identity change for %s: %s", from_jid, exc)
            return {"action": "session_refresh_failed", "error": str(exc)}

    return {"action": "session_refreshed"}


def handle_identity_change(state: Mapping[str, object], jid: str) -> dict[str, object]:
    """Legacy helper for updating state dictionary."""
    out = dict(state)
    out["session_stale"] = True
    out["stale_jid"] = jid
    return out
