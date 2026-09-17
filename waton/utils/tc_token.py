"""Trusted Contact (TC) token handling and lifecycle.

Implements rolling 7-day buckets (~28-day window) for WhatsApp privacy/TC tokens.
Mirrors Baileys `src/Utils/tc-token-utils.ts` and whatsmeow `tctoken.go`.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from waton.protocol.binary_node import BinaryNode

if TYPE_CHECKING:
    from waton.utils.auth import StoragePort

TC_TOKEN_BUCKET_DURATION = 604800  # 7 days in seconds
TC_TOKEN_NUM_BUCKETS = 4  # ~28-day rolling window
TC_TOKEN_NAMESPACE = "tctoken"


def is_tc_token_expired(timestamp: int | str | None, current_time: int | None = None) -> bool:
    """Returns True if the TC token timestamp is expired or invalid."""
    if timestamp is None:
        return True
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return True

    now = int(current_time if current_time is not None else time.time())
    current_bucket = now // TC_TOKEN_BUCKET_DURATION
    cutoff_bucket = current_bucket - (TC_TOKEN_NUM_BUCKETS - 1)
    cutoff_timestamp = cutoff_bucket * TC_TOKEN_BUCKET_DURATION
    return ts < cutoff_timestamp


def should_send_new_tc_token(sender_timestamp: int | str | None, current_time: int | None = None) -> bool:
    """Returns True if the current bucket is newer than the last issuance bucket."""
    if sender_timestamp is None:
        return True
    try:
        ts = int(sender_timestamp)
    except (ValueError, TypeError):
        return True

    now = int(current_time if current_time is not None else time.time())
    current_bucket = now // TC_TOKEN_BUCKET_DURATION
    sender_bucket = ts // TC_TOKEN_BUCKET_DURATION
    return current_bucket > sender_bucket


def build_tc_token_node(token: bytes, timestamp: int | str) -> BinaryNode:
    """Builds a <tctoken t="...">...</tctoken> binary node."""
    return BinaryNode(
        tag="tctoken",
        attrs={"t": str(timestamp)},
        content=token,
    )


def extract_tc_tokens(node: BinaryNode, fallback_jid: str = "") -> list[dict[str, Any]]:
    """
    Extracts trusted contact tokens from an IQ result node or privacy_token notification node.
    Returns list of dicts with: jid, token (bytes), timestamp (int).
    """
    results: list[dict[str, Any]] = []

    # Check for direct tokens container or inside children
    tokens_container = None
    if node.tag == "tokens":
        tokens_container = node
    elif isinstance(node.content, list):
        for child in node.content:
            if child.tag in {"tokens", "privacy_token"}:
                tokens_container = child
                break

    if not tokens_container or not isinstance(tokens_container.content, list):
        return results

    for item in tokens_container.content:
        if item.tag != "token":
            continue
        token_type = item.attrs.get("type")
        if token_type not in {None, "trusted_contact"}:
            continue

        raw_content = item.content
        token_bytes: bytes | None = None
        if isinstance(raw_content, (bytes, bytearray)):
            token_bytes = bytes(raw_content)
        elif isinstance(raw_content, str):
            token_bytes = raw_content.encode("utf-8")

        if not token_bytes:
            continue

        target_jid = item.attrs.get("jid") or fallback_jid or node.attrs.get("from", "")
        # Remove resource/device suffix for user level token
        clean_jid = target_jid.split(":")[0] + "@" + target_jid.split("@")[-1] if ":" in target_jid else target_jid

        ts_str = item.attrs.get("t")
        try:
            ts = int(ts_str) if ts_str is not None else int(time.time())
        except (ValueError, TypeError):
            ts = int(time.time())

        results.append({
            "jid": clean_jid,
            "token": token_bytes,
            "timestamp": ts,
        })

    return results


class TCTokenManager:
    """In-memory and storage-backed manager for trusted contact tokens."""

    def __init__(self, storage: StoragePort | None = None) -> None:
        self.storage = storage
        self._tokens: dict[str, dict[str, Any]] = {}
        self._sender_timestamps: dict[str, int] = {}

    def get_token(self, jid: str) -> dict[str, Any] | None:
        """Returns valid (unexpired) token dict for JID if present."""
        clean_jid = jid.split(":")[0] + "@" + jid.split("@")[-1] if ":" in jid else jid
        entry = self._tokens.get(clean_jid)
        if not entry:
            return None
        ts = entry.get("timestamp")
        if is_tc_token_expired(ts):
            self._tokens.pop(clean_jid, None)
            return None
        return entry

    def save_token(self, jid: str, token: bytes, timestamp: int | str) -> None:
        """Stores a peer's trusted contact token."""
        clean_jid = jid.split(":")[0] + "@" + jid.split("@")[-1] if ":" in jid else jid
        try:
            ts = int(timestamp)
        except (ValueError, TypeError):
            ts = int(time.time())

        self._tokens[clean_jid] = {
            "token": token,
            "timestamp": ts,
        }

    def record_sender_timestamp(self, jid: str, timestamp: int | None = None) -> None:
        """Records our own last token issuance timestamp to this peer."""
        clean_jid = jid.split(":")[0] + "@" + jid.split("@")[-1] if ":" in jid else jid
        self._sender_timestamps[clean_jid] = timestamp if timestamp is not None else int(time.time())

    def should_issue_to(self, jid: str) -> bool:
        """Checks if a new token should be issued to this peer."""
        clean_jid = jid.split(":")[0] + "@" + jid.split("@")[-1] if ":" in jid else jid
        sender_ts = self._sender_timestamps.get(clean_jid)
        return should_send_new_tc_token(sender_ts)
