"""Retry state management for send/retry receipt flows.

This mirrors core behavior from Baileys' MessageRetryManager while keeping a
Python-first API surface.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable

MESSAGE_KEY_SEPARATOR = "\x00"
RECREATE_SESSION_TIMEOUT_MS = 60 * 60 * 1000
PHONE_REQUEST_DELAY_MS = 3000
MAC_ERROR_CODES = {4, 7}


class RetryReason(IntEnum):
    UnknownError = 0
    SignalErrorNoSession = 1
    SignalErrorInvalidKey = 2
    SignalErrorInvalidKeyId = 3
    SignalErrorInvalidMessage = 4
    SignalErrorInvalidSignature = 5
    SignalErrorFutureMessage = 6
    SignalErrorBadMac = 7
    SignalErrorInvalidSession = 8
    SignalErrorInvalidMsgKey = 9
    BadBroadcastEphemeralSetting = 10
    UnknownCompanionNoPrekey = 11
    AdvFailure = 12
    StatusRevokeDelay = 13


@dataclass
class RetryEntry:
    message_id: str
    retry_count: int = 0
    sent_once: bool = False
    retry_acked: bool = False
    last_retry_ts: int | None = None
    last_error: str | None = None


@dataclass
class RecentMessage:
    message: Any
    timestamp: int


class RetryManager:
    def __init__(self, max_attempts: int = 3, *, max_recent_messages: int = 512) -> None:
        self.max_attempts = max_attempts
        self.max_recent_messages = max_recent_messages
        self._entries: dict[str, RetryEntry] = {}
        self._recent_messages: dict[str, RecentMessage] = {}
        self._message_key_index: dict[str, str] = {}
        self._session_recreate_history: dict[str, int] = {}
        self._pending_phone_requests: dict[str, threading.Timer] = {}
        self._statistics: dict[str, int] = {
            "totalRetries": 0,
            "successfulRetries": 0,
            "failedRetries": 0,
            "mediaRetries": 0,
            "sessionRecreations": 0,
            "phoneRequests": 0,
        }

    def _entry(self, message_id: str) -> RetryEntry:
        entry = self._entries.get(message_id)
        if entry is None:
            entry = RetryEntry(message_id=message_id)
            self._entries[message_id] = entry
        return entry

    def _message_key(self, to: str, message_id: str) -> str:
        return f"{to}{MESSAGE_KEY_SEPARATOR}{message_id}"

    def _remove_recent_message(self, message_id: str) -> None:
        key = self._message_key_index.pop(message_id, None)
        if key is None:
            return
        self._recent_messages.pop(key, None)

    def should_send(self, message_id: str, *, force: bool = False) -> bool:
        entry = self._entry(message_id)
        if force:
            entry.sent_once = True
            return True
        if entry.sent_once:
            return False
        entry.sent_once = True
        return True

    def mark_sent(self, message_id: str) -> None:
        self._entry(message_id).sent_once = True

    def register_retry(self, message_id: str, *, error: str | None = None, timestamp: int | None = None) -> int:
        entry = self._entry(message_id)
        entry.retry_count += 1
        entry.last_retry_ts = int(time.time()) if timestamp is None else timestamp
        entry.last_error = error
        self._statistics["totalRetries"] += 1
        return entry.retry_count

    def increment_retry_count(self, message_id: str) -> int:
        return self.register_retry(message_id)

    def should_retry(self, message_id: str) -> bool:
        entry = self._entry(message_id)
        if entry.retry_acked:
            return False
        return entry.retry_count <= self.max_attempts

    def has_exceeded_max_retries(self, message_id: str) -> bool:
        return self.get_retry_count(message_id) >= self.max_attempts

    def mark_retry_acked(self, message_id: str) -> None:
        entry = self._entry(message_id)
        entry.retry_acked = True

    def mark_retry_success(self, message_id: str) -> None:
        self._statistics["successfulRetries"] += 1
        self.clear(message_id)
        self.cancel_pending_phone_request(message_id)
        self._remove_recent_message(message_id)

    def mark_retry_failed(self, message_id: str) -> None:
        self._statistics["failedRetries"] += 1
        self.clear(message_id)
        self.cancel_pending_phone_request(message_id)
        self._remove_recent_message(message_id)

    def get_retry_count(self, message_id: str) -> int:
        return self._entry(message_id).retry_count

    def get_last_retry_ts(self, message_id: str) -> int | None:
        return self._entry(message_id).last_retry_ts

    def parse_retry_error_code(self, error_attr: str | None) -> RetryReason | None:
        if error_attr is None or error_attr == "":
            return None
        try:
            code = int(error_attr)
        except ValueError:
            return None
        if code in {reason.value for reason in RetryReason}:
            return RetryReason(code)
        return RetryReason.UnknownError

    def is_mac_error(self, error_code: RetryReason | None) -> bool:
        return error_code is not None and int(error_code) in MAC_ERROR_CODES

    def should_recreate_session(
        self,
        jid: str,
        *,
        has_session: bool,
        error_code: RetryReason | None = None,
        now_ms: int | None = None,
    ) -> dict[str, Any]:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        if not has_session:
            self._session_recreate_history[jid] = now
            self._statistics["sessionRecreations"] += 1
            return {"reason": "missing_session", "recreate": True}

        if self.is_mac_error(error_code):
            self._session_recreate_history[jid] = now
            self._statistics["sessionRecreations"] += 1
            return {"reason": f"mac_error_{int(error_code)}", "recreate": True}

        previous = self._session_recreate_history.get(jid)
        if previous is None or now - previous > RECREATE_SESSION_TIMEOUT_MS:
            self._session_recreate_history[jid] = now
            self._statistics["sessionRecreations"] += 1
            return {"reason": "recreate_timeout_elapsed", "recreate": True}

        return {"reason": "", "recreate": False}

    def add_recent_message(self, to: str, message_id: str, message: Any, *, timestamp_ms: int | None = None) -> None:
        timestamp = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
        key = self._message_key(to, message_id)
        self._recent_messages[key] = RecentMessage(message=message, timestamp=timestamp)
        self._message_key_index[message_id] = key

        while len(self._recent_messages) > self.max_recent_messages:
            oldest_key = next(iter(self._recent_messages.keys()))
            self._recent_messages.pop(oldest_key, None)
            separator_index = oldest_key.rfind(MESSAGE_KEY_SEPARATOR)
            if separator_index > -1:
                old_message_id = oldest_key[separator_index + 1 :]
                self._message_key_index.pop(old_message_id, None)

    def get_recent_message(self, to: str, message_id: str) -> dict[str, Any] | None:
        key = self._message_key(to, message_id)
        data = self._recent_messages.get(key)
        if data is None:
            return None
        return {"message": data.message, "timestamp": data.timestamp}

    def get_recent_message_by_id(self, message_id: str) -> dict[str, Any] | None:
        key = self._message_key_index.get(message_id)
        if key is None:
            return None
        data = self._recent_messages.get(key)
        if data is None:
            return None
        return {"message": data.message, "timestamp": data.timestamp}

    def schedule_phone_request(
        self,
        message_id: str,
        callback: Callable[[], None],
        *,
        delay_ms: int = PHONE_REQUEST_DELAY_MS,
    ) -> None:
        self.cancel_pending_phone_request(message_id)

        def _fire() -> None:
            self._pending_phone_requests.pop(message_id, None)
            self._statistics["phoneRequests"] += 1
            callback()

        timer = threading.Timer(delay_ms / 1000.0, _fire)
        self._pending_phone_requests[message_id] = timer
        timer.daemon = True
        timer.start()

    def cancel_pending_phone_request(self, message_id: str) -> None:
        timer = self._pending_phone_requests.pop(message_id, None)
        if timer is not None:
            timer.cancel()

    def get_statistics(self) -> dict[str, int]:
        return dict(self._statistics)

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {
            message_id: {
                "retry_count": entry.retry_count,
                "sent_once": entry.sent_once,
                "retry_acked": entry.retry_acked,
                "last_retry_ts": entry.last_retry_ts,
                "last_error": entry.last_error,
            }
            for message_id, entry in self._entries.items()
        }

    def clear(self, message_id: str) -> None:
        self._entries.pop(message_id, None)

    def clear_stale(self, *, max_age_seconds: int, now_ts: int | None = None) -> int:
        now = int(time.time()) if now_ts is None else now_ts
        removed = 0
        for message_id in list(self._entries.keys()):
            entry = self._entries[message_id]
            if entry.last_retry_ts is None:
                continue
            if now - entry.last_retry_ts > max_age_seconds:
                self._entries.pop(message_id, None)
                removed += 1
        return removed

    def close(self) -> None:
        for message_id in list(self._pending_phone_requests.keys()):
            self.cancel_pending_phone_request(message_id)
