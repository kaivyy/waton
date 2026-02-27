"""Minimal protobuf wire helpers for WhatsApp connection handshake payloads.

This module intentionally implements only the subset needed by waton transport
connection/auth flow. High-level message payloads still use ``wa_pb2.Message``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode negative values")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("unexpected EOF while decoding varint")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7
        if shift >= 64:
            raise ValueError("varint too long")


def _key(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _encode_len_delimited(field_number: int, payload: bytes) -> bytes:
    if not payload:
        return b""
    return _key(field_number, 2) + _encode_varint(len(payload)) + payload


def _encode_string(field_number: int, value: str | None) -> bytes:
    if value is None or value == "":
        return b""
    return _encode_len_delimited(field_number, value.encode("utf-8"))


def _encode_bytes(field_number: int, value: bytes | None) -> bytes:
    if value is None or value == b"":
        return b""
    return _encode_len_delimited(field_number, value)


def _encode_varint_field(field_number: int, value: int | None) -> bytes:
    if value is None:
        return b""
    return _key(field_number, 0) + _encode_varint(value)


def _encode_bool(field_number: int, value: bool | None) -> bytes:
    if value is None:
        return b""
    return _encode_varint_field(field_number, 1 if value else 0)


def _iter_fields(data: bytes) -> Iterable[tuple[int, int, bytes | int]]:
    offset = 0
    while offset < len(data):
        key, offset = _decode_varint(data, offset)
        field_number = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, offset = _decode_varint(data, offset)
            yield field_number, wire_type, value
            continue
        if wire_type == 1:
            if offset + 8 > len(data):
                raise ValueError("unexpected EOF in fixed64 field")
            value = data[offset : offset + 8]
            offset += 8
            yield field_number, wire_type, value
            continue
        if wire_type == 2:
            size, offset = _decode_varint(data, offset)
            end = offset + size
            if end > len(data):
                raise ValueError("unexpected EOF in len-delimited field")
            value = data[offset:end]
            offset = end
            yield field_number, wire_type, value
            continue
        if wire_type == 5:
            if offset + 4 > len(data):
                raise ValueError("unexpected EOF in fixed32 field")
            value = data[offset : offset + 4]
            offset += 4
            yield field_number, wire_type, value
            continue
        raise ValueError(f"unsupported wire type: {wire_type}")


@dataclass
class HandshakeClientHello:
    ephemeral: bytes | None = None
    static: bytes | None = None
    payload: bytes | None = None
    use_extended: bool | None = None
    extended_ciphertext: bytes | None = None

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_bytes(1, self.ephemeral),
                _encode_bytes(2, self.static),
                _encode_bytes(3, self.payload),
                _encode_bool(4, self.use_extended),
                _encode_bytes(5, self.extended_ciphertext),
            )
        )

    @classmethod
    def ParseFromString(cls, payload: bytes) -> "HandshakeClientHello":
        out = cls()
        for field, wire, value in _iter_fields(payload):
            if wire == 2 and field == 1:
                out.ephemeral = value  # type: ignore[assignment]
            elif wire == 2 and field == 2:
                out.static = value  # type: ignore[assignment]
            elif wire == 2 and field == 3:
                out.payload = value  # type: ignore[assignment]
            elif wire == 0 and field == 4:
                out.use_extended = bool(value)
            elif wire == 2 and field == 5:
                out.extended_ciphertext = value  # type: ignore[assignment]
        return out


@dataclass
class HandshakeServerHello:
    ephemeral: bytes | None = None
    static: bytes | None = None
    payload: bytes | None = None
    extended_static: bytes | None = None

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_bytes(1, self.ephemeral),
                _encode_bytes(2, self.static),
                _encode_bytes(3, self.payload),
                _encode_bytes(4, self.extended_static),
            )
        )

    @classmethod
    def ParseFromString(cls, payload: bytes) -> "HandshakeServerHello":
        out = cls()
        for field, wire, value in _iter_fields(payload):
            if wire == 2 and field == 1:
                out.ephemeral = value  # type: ignore[assignment]
            elif wire == 2 and field == 2:
                out.static = value  # type: ignore[assignment]
            elif wire == 2 and field == 3:
                out.payload = value  # type: ignore[assignment]
            elif wire == 2 and field == 4:
                out.extended_static = value  # type: ignore[assignment]
        return out


@dataclass
class HandshakeClientFinish:
    static: bytes | None = None
    payload: bytes | None = None
    extended_ciphertext: bytes | None = None

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_bytes(1, self.static),
                _encode_bytes(2, self.payload),
                _encode_bytes(3, self.extended_ciphertext),
            )
        )

    @classmethod
    def ParseFromString(cls, payload: bytes) -> "HandshakeClientFinish":
        out = cls()
        for field, wire, value in _iter_fields(payload):
            if wire == 2 and field == 1:
                out.static = value  # type: ignore[assignment]
            elif wire == 2 and field == 2:
                out.payload = value  # type: ignore[assignment]
            elif wire == 2 and field == 3:
                out.extended_ciphertext = value  # type: ignore[assignment]
        return out


@dataclass
class HandshakeMessage:
    client_hello: HandshakeClientHello | None = None
    server_hello: HandshakeServerHello | None = None
    client_finish: HandshakeClientFinish | None = None

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_len_delimited(2, self.client_hello.SerializeToString())
                if self.client_hello
                else b"",
                _encode_len_delimited(3, self.server_hello.SerializeToString())
                if self.server_hello
                else b"",
                _encode_len_delimited(4, self.client_finish.SerializeToString())
                if self.client_finish
                else b"",
            )
        )

    @classmethod
    def ParseFromString(cls, payload: bytes) -> "HandshakeMessage":
        out = cls()
        for field, wire, value in _iter_fields(payload):
            if wire != 2:
                continue
            if field == 2:
                out.client_hello = HandshakeClientHello.ParseFromString(value)  # type: ignore[arg-type]
            elif field == 3:
                out.server_hello = HandshakeServerHello.ParseFromString(value)  # type: ignore[arg-type]
            elif field == 4:
                out.client_finish = HandshakeClientFinish.ParseFromString(value)  # type: ignore[arg-type]
        return out


@dataclass
class AppVersion:
    primary: int | None = None
    secondary: int | None = None
    tertiary: int | None = None
    quaternary: int | None = None
    quinary: int | None = None

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_varint_field(1, self.primary),
                _encode_varint_field(2, self.secondary),
                _encode_varint_field(3, self.tertiary),
                _encode_varint_field(4, self.quaternary),
                _encode_varint_field(5, self.quinary),
            )
        )


@dataclass
class UserAgent:
    platform: int | None = None
    app_version: AppVersion | None = None
    mcc: str | None = None
    mnc: str | None = None
    os_version: str | None = None
    manufacturer: str | None = None
    device: str | None = None
    os_build_number: str | None = None
    phone_id: str | None = None
    release_channel: int | None = None
    locale_language_iso6391: str | None = None
    locale_country_iso31661_alpha2: str | None = None

    class Platform:
        WEB = 14

    class ReleaseChannel:
        RELEASE = 0

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_varint_field(1, self.platform),
                _encode_len_delimited(2, self.app_version.SerializeToString())
                if self.app_version
                else b"",
                _encode_string(3, self.mcc),
                _encode_string(4, self.mnc),
                _encode_string(5, self.os_version),
                _encode_string(6, self.manufacturer),
                _encode_string(7, self.device),
                _encode_string(8, self.os_build_number),
                _encode_string(9, self.phone_id),
                _encode_varint_field(10, self.release_channel),
                _encode_string(11, self.locale_language_iso6391),
                _encode_string(12, self.locale_country_iso31661_alpha2),
            )
        )


@dataclass
class WebInfo:
    web_sub_platform: int | None = None

    class WebSubPlatform:
        WEB_BROWSER = 0
        DARWIN = 3
        WIN32 = 4

    def SerializeToString(self) -> bytes:
        return _encode_varint_field(4, self.web_sub_platform)


@dataclass
class DevicePairingRegistrationData:
    e_regid: bytes | None = None
    e_keytype: bytes | None = None
    e_ident: bytes | None = None
    e_skey_id: bytes | None = None
    e_skey_val: bytes | None = None
    e_skey_sig: bytes | None = None
    build_hash: bytes | None = None
    device_props: bytes | None = None

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_bytes(1, self.e_regid),
                _encode_bytes(2, self.e_keytype),
                _encode_bytes(3, self.e_ident),
                _encode_bytes(4, self.e_skey_id),
                _encode_bytes(5, self.e_skey_val),
                _encode_bytes(6, self.e_skey_sig),
                _encode_bytes(7, self.build_hash),
                _encode_bytes(8, self.device_props),
            )
        )


@dataclass
class ClientPayload:
    username: int | None = None
    passive: bool | None = None
    user_agent: UserAgent | None = None
    web_info: WebInfo | None = None
    connect_type: int | None = None
    connect_reason: int | None = None
    device: int | None = None
    device_pairing_data: DevicePairingRegistrationData | None = None
    pull: bool | None = None
    lid_db_migrated: bool | None = None

    class ConnectType:
        WIFI_UNKNOWN = 1

    class ConnectReason:
        USER_ACTIVATED = 1

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_varint_field(1, self.username),
                _encode_bool(3, self.passive),
                _encode_len_delimited(5, self.user_agent.SerializeToString())
                if self.user_agent
                else b"",
                _encode_len_delimited(6, self.web_info.SerializeToString())
                if self.web_info
                else b"",
                _encode_varint_field(12, self.connect_type),
                _encode_varint_field(13, self.connect_reason),
                _encode_varint_field(18, self.device),
                _encode_len_delimited(19, self.device_pairing_data.SerializeToString())
                if self.device_pairing_data
                else b"",
                _encode_bool(33, self.pull),
                _encode_bool(41, self.lid_db_migrated),
            )
        )


@dataclass
class HistorySyncConfig:
    storage_quota_mb: int | None = None
    inline_initial_payload_in_e2ee_msg: bool | None = None
    support_call_log_history: bool | None = None
    support_bot_user_agent_chat_history: bool | None = None
    support_cag_reactions_and_polls: bool | None = None
    support_biz_hosted_msg: bool | None = None
    support_recent_sync_chunk_message_count_tuning: bool | None = None
    support_hosted_group_msg: bool | None = None
    support_fbid_bot_chat_history: bool | None = None
    support_message_association: bool | None = None
    support_group_history: bool | None = None

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_varint_field(3, self.storage_quota_mb),
                _encode_bool(4, self.inline_initial_payload_in_e2ee_msg),
                _encode_bool(6, self.support_call_log_history),
                _encode_bool(7, self.support_bot_user_agent_chat_history),
                _encode_bool(8, self.support_cag_reactions_and_polls),
                _encode_bool(9, self.support_biz_hosted_msg),
                _encode_bool(10, self.support_recent_sync_chunk_message_count_tuning),
                _encode_bool(11, self.support_hosted_group_msg),
                _encode_bool(12, self.support_fbid_bot_chat_history),
                _encode_bool(14, self.support_message_association),
                _encode_bool(15, self.support_group_history),
            )
        )


@dataclass
class DevicePropsAppVersion:
    primary: int | None = None
    secondary: int | None = None
    tertiary: int | None = None

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_varint_field(1, self.primary),
                _encode_varint_field(2, self.secondary),
                _encode_varint_field(3, self.tertiary),
            )
        )


@dataclass
class DeviceProps:
    os: str | None = None
    version: DevicePropsAppVersion | None = None
    platform_type: int | None = None
    require_full_sync: bool | None = None
    history_sync_config: HistorySyncConfig | None = None

    class PlatformType:
        CHROME = 1
        DESKTOP = 7

    def SerializeToString(self) -> bytes:
        return b"".join(
            (
                _encode_string(1, self.os),
                _encode_len_delimited(2, self.version.SerializeToString())
                if self.version
                else b"",
                _encode_varint_field(3, self.platform_type),
                _encode_bool(4, self.require_full_sync),
                _encode_len_delimited(5, self.history_sync_config.SerializeToString())
                if self.history_sync_config
                else b"",
            )
        )


@dataclass
class ADVSignedDeviceIdentityHMAC:
    details: bytes | None = None
    hmac: bytes | None = None
    account_type: int | None = None

    class ADVEncryptionType:
        E2EE = 0
        HOSTED = 1

    @classmethod
    def ParseFromString(cls, payload: bytes) -> "ADVSignedDeviceIdentityHMAC":
        out = cls()
        for field, wire, value in _iter_fields(payload):
            if wire == 2 and field == 1:
                out.details = value  # type: ignore[assignment]
            elif wire == 2 and field == 2:
                out.hmac = value  # type: ignore[assignment]
            elif wire == 0 and field == 3:
                out.account_type = int(value)  # type: ignore[arg-type]
        return out


@dataclass
class ADVSignedDeviceIdentity:
    details: bytes | None = None
    account_signature_key: bytes | None = None
    account_signature: bytes | None = None
    device_signature: bytes | None = None

    @classmethod
    def ParseFromString(cls, payload: bytes) -> "ADVSignedDeviceIdentity":
        out = cls()
        for field, wire, value in _iter_fields(payload):
            if wire == 2 and field == 1:
                out.details = value  # type: ignore[assignment]
            elif wire == 2 and field == 2:
                out.account_signature_key = value  # type: ignore[assignment]
            elif wire == 2 and field == 3:
                out.account_signature = value  # type: ignore[assignment]
            elif wire == 2 and field == 4:
                out.device_signature = value  # type: ignore[assignment]
        return out

    def SerializeToString(self, *, include_signature_key: bool) -> bytes:
        return b"".join(
            (
                _encode_bytes(1, self.details),
                _encode_bytes(2, self.account_signature_key if include_signature_key else None),
                _encode_bytes(3, self.account_signature),
                _encode_bytes(4, self.device_signature),
            )
        )


@dataclass
class ADVDeviceIdentity:
    raw_id: int | None = None
    timestamp: int | None = None
    key_index: int | None = None
    account_type: int | None = None
    device_type: int | None = None

    class ADVEncryptionType:
        E2EE = 0
        HOSTED = 1

    @classmethod
    def ParseFromString(cls, payload: bytes) -> "ADVDeviceIdentity":
        out = cls()
        for field, wire, value in _iter_fields(payload):
            if wire == 0 and field == 1:
                out.raw_id = int(value)  # type: ignore[arg-type]
            elif wire == 0 and field == 2:
                out.timestamp = int(value)  # type: ignore[arg-type]
            elif wire == 0 and field == 3:
                out.key_index = int(value)  # type: ignore[arg-type]
            elif wire == 0 and field == 4:
                out.account_type = int(value)  # type: ignore[arg-type]
            elif wire == 0 and field == 5:
                out.device_type = int(value)  # type: ignore[arg-type]
        return out

