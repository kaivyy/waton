# ruff: noqa: N802, N815, N999
"""Minimal WAProto subset with real protobuf wire encoding.

This module intentionally implements only fields currently used by waton:
- Message.conversation
- Message.extendedTextMessage.text
- Message.reactionMessage.{key,text}
- Message.deviceSentMessage.{destinationJid,message}
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .wire import _encode_bool, _encode_len_delimited, _encode_string, _iter_fields


@dataclass
class MessageKey:
    remoteJid: str = ""
    fromMe: bool = False
    id: str = ""
    participant: str = ""

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_string(1, self.remoteJid),
                _encode_bool(2, self.fromMe if self.fromMe else None),
                _encode_string(3, self.id),
                _encode_string(4, self.participant),
            )
        )

    def ParseFromString(self, data: bytes) -> None:
        for field_no, wire_type, value in _iter_fields(data):
            if wire_type == 2 and field_no == 1:
                self.remoteJid = bytes(value).decode("utf-8", errors="ignore")
            elif wire_type == 0 and field_no == 2:
                self.fromMe = bool(int(value))
            elif wire_type == 2 and field_no == 3:
                self.id = bytes(value).decode("utf-8", errors="ignore")
            elif wire_type == 2 and field_no == 4:
                self.participant = bytes(value).decode("utf-8", errors="ignore")


@dataclass
class ReactionMessage:
    key: MessageKey = field(default_factory=MessageKey)
    text: str = ""

    def SerializeToString(self) -> bytes:
        key_payload = self.key.SerializeToString()
        return b"".join(
            (
                _encode_len_delimited(1, key_payload) if key_payload else b"",
                _encode_string(2, self.text),
            )
        )

    def ParseFromString(self, data: bytes) -> None:
        for field_no, wire_type, value in _iter_fields(data):
            if wire_type == 2 and field_no == 1:
                self.key.ParseFromString(bytes(value))
            elif wire_type == 2 and field_no == 2:
                self.text = bytes(value).decode("utf-8", errors="ignore")


@dataclass
class ExtendedTextMessage:
    text: str = ""

    def SerializeToString(self) -> bytes:
        return _encode_string(1, self.text)

    def ParseFromString(self, data: bytes) -> None:
        for field_no, wire_type, value in _iter_fields(data):
            if wire_type == 2 and field_no == 1:
                self.text = bytes(value).decode("utf-8", errors="ignore")


class Message:
    class _NoDeviceSentMessage:
        def __init__(self) -> None:
            self.destinationJid = ""
            self.message = None

        def SerializeToString(self) -> bytes:
            return b""

        def ParseFromString(self, data: bytes) -> None:
            _ = data

    class _DeviceSentMessage:
        def __init__(self) -> None:
            self.destinationJid = ""
            self.message = Message(_include_device_sent=False)

        def SerializeToString(self) -> bytes:
            nested = self.message.SerializeToString()
            return b"".join(
                (
                    _encode_string(1, self.destinationJid),
                    _encode_len_delimited(2, nested) if nested else b"",
                )
            )

        def ParseFromString(self, data: bytes) -> None:
            for field_no, wire_type, value in _iter_fields(data):
                if wire_type == 2 and field_no == 1:
                    self.destinationJid = bytes(value).decode("utf-8", errors="ignore")
                elif wire_type == 2 and field_no == 2:
                    self.message.ParseFromString(bytes(value))

    def __init__(self, _include_device_sent: bool = True) -> None:
        self.conversation = ""
        self.extendedTextMessage = ExtendedTextMessage()
        self.reactionMessage = ReactionMessage()
        self.deviceSentMessage = (
            Message._DeviceSentMessage() if _include_device_sent else Message._NoDeviceSentMessage()
        )

    def SerializeToString(self) -> bytes:
        ext = self.extendedTextMessage.SerializeToString()
        react = self.reactionMessage.SerializeToString()
        device_sent = self.deviceSentMessage.SerializeToString()
        return b"".join(
            (
                _encode_string(1, self.conversation),
                _encode_len_delimited(6, ext) if ext else b"",
                _encode_len_delimited(31, device_sent) if device_sent else b"",
                _encode_len_delimited(46, react) if react else b"",
            )
        )

    def ParseFromString(self, data: bytes) -> None:
        try:
            for field_no, wire_type, value in _iter_fields(data):
                if wire_type != 2:
                    continue
                payload = bytes(value)
                if field_no == 1:
                    self.conversation = payload.decode("utf-8", errors="ignore")
                elif field_no == 6:
                    self.extendedTextMessage.ParseFromString(payload)
                elif field_no == 31:
                    self.deviceSentMessage.ParseFromString(payload)
                elif field_no == 46:
                    self.reactionMessage.ParseFromString(payload)
        except Exception:
            self.conversation = data.decode("utf-8", errors="ignore")
