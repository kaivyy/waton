from __future__ import annotations

from typing import Any

from waton.protocol.binary_node import BinaryNode
from waton.utils.crypto import hkdf, hmac_sha256

REPORTING_FIELDS = [
    {"f": 1},
    {"f": 3, "s": [{"f": 2}, {"f": 3}, {"f": 8}, {"f": 11}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}, {"f": 25}]},
    {"f": 4, "s": [{"f": 1}, {"f": 16}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}]},
    {"f": 5, "s": [{"f": 3}, {"f": 4}, {"f": 5}, {"f": 16}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}]},
    {"f": 6, "s": [{"f": 1}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}, {"f": 30}]},
    {"f": 7, "s": [{"f": 2}, {"f": 7}, {"f": 10}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}, {"f": 20}]},
    {"f": 8, "s": [{"f": 2}, {"f": 7}, {"f": 9}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}, {"f": 21}]},
    {"f": 9, "s": [{"f": 2}, {"f": 6}, {"f": 7}, {"f": 13}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}, {"f": 20}]},
    {"f": 12, "s": [{"f": 1}, {"f": 2}, {"f": 14, "m": True}, {"f": 15}]},
    {"f": 18, "s": [{"f": 6}, {"f": 16}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}]},
    {"f": 26, "s": [{"f": 4}, {"f": 5}, {"f": 8}, {"f": 13}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}]},
    {"f": 28, "s": [{"f": 1}, {"f": 2}, {"f": 4}, {"f": 5}, {"f": 6}, {"f": 7, "s": [{"f": 21}, {"f": 22}]}]},
    {"f": 37, "s": [{"f": 1, "m": True}]},
    {"f": 49, "s": [{"f": 2}, {"f": 3, "s": [{"f": 1}, {"f": 2}]}, {"f": 5, "s": [{"f": 21}, {"f": 22}]}, {"f": 8, "s": [{"f": 1}, {"f": 2}]}]},
    {"f": 53, "s": [{"f": 1, "m": True}]},
    {"f": 55, "s": [{"f": 1, "m": True}]},
    {"f": 58, "s": [{"f": 1, "m": True}]},
    {"f": 59, "s": [{"f": 1, "m": True}]},
    {"f": 60, "s": [{"f": 2}, {"f": 3, "s": [{"f": 1}, {"f": 2}]}, {"f": 5, "s": [{"f": 21}, {"f": 22}]}, {"f": 8, "s": [{"f": 1}, {"f": 2}]}]},
    {"f": 64, "s": [{"f": 2}, {"f": 3, "s": [{"f": 1}, {"f": 2}]}, {"f": 5, "s": [{"f": 21}, {"f": 22}]}, {"f": 8, "s": [{"f": 1}, {"f": 2}]}]},
    {"f": 66, "s": [{"f": 2}, {"f": 6}, {"f": 7}, {"f": 13}, {"f": 17, "s": [{"f": 21}, {"f": 22}]}, {"f": 20}]},
    {"f": 74, "s": [{"f": 1, "m": True}]},
    {"f": 87, "s": [{"f": 1, "m": True}]},
    {"f": 88, "s": [{"f": 1}, {"f": 2, "s": [{"f": 1}]}, {"f": 3, "s": [{"f": 21}, {"f": 22}]}]},
    {"f": 92, "s": [{"f": 1, "m": True}]},
    {"f": 93, "s": [{"f": 1, "m": True}]},
    {"f": 94, "s": [{"f": 1, "m": True}]}
]

def should_include_reporting_token(message_dict: dict[str, Any]) -> bool:
    """Checks if a message dictionary should include a reporting token."""
    return (
        "reactionMessage" not in message_dict
        and "encReactionMessage" not in message_dict
        and "encEventResponseMessage" not in message_dict
        and "pollUpdateMessage" not in message_dict
    )

def _decode_varint(data: bytes, offset: int) -> tuple[int, int, bool]:
    value = 0
    bytes_read = 0
    shift = 0
    while offset + bytes_read < len(data):
        current = data[offset + bytes_read]
        value |= (current & 0x7F) << shift
        bytes_read += 1
        if (current & 0x80) == 0:
            return value, bytes_read, True
        shift += 7
        if shift > 35:
            return 0, 0, False
    return 0, 0, False

def _encode_varint(value: int) -> bytes:
    parts = bytearray()
    remaining = value
    while remaining > 0x7F:
        parts.append((remaining & 0x7F) | 0x80)
        remaining >>= 7
    parts.append(remaining)
    return bytes(parts)

def _extract_reporting_token_content(data: bytes, fields_config: list[dict[str, Any]]) -> bytes:
    config_map = {f["f"]: f for f in fields_config}
    out = []
    i = 0
    while i < len(data):
        tag, tag_len, ok = _decode_varint(data, i)
        if not ok or tag_len <= 0:
            return b""
        
        field_num = tag >> 3
        wire_type = tag & 0x7
        field_start = i
        i += tag_len
        
        field_cfg = config_map.get(field_num)
        
        if field_cfg is None:
            if wire_type == 0:
                _, n, _ = _decode_varint(data, i)
                i += n
            elif wire_type == 1:
                i += 8
            elif wire_type == 2:
                l, n, _ = _decode_varint(data, i)
                i += n + l
            elif wire_type == 5:
                i += 4
            else:
                return b""
            continue
            
        if wire_type == 0:
            _, n, _ = _decode_varint(data, i)
            i += n
            out.append((field_num, data[field_start:i]))
        elif wire_type == 1:
            i += 8
            out.append((field_num, data[field_start:i]))
        elif wire_type == 2:
            l, n, _ = _decode_varint(data, i)
            val_start = i + n
            val_end = val_start + l
            if field_cfg.get("m") or "s" in field_cfg:
                sub = _extract_reporting_token_content(data[val_start:val_end], field_cfg.get("s", []))
                if len(sub) > 0:
                    encoded_len = _encode_varint(len(sub))
                    tag_buf = _encode_varint(tag)
                    out.append((field_num, tag_buf + encoded_len + sub))
            else:
                out.append((field_num, data[field_start:val_end]))
            i = val_end
        elif wire_type == 5:
            i += 4
            out.append((field_num, data[field_start:i]))
        else:
            return b""
            
    out.sort(key=lambda x: x[0])
    return b"".join(x[1] for x in out)

def get_message_reporting_token(
    message_secret: bytes,
    message_bytes: bytes,
    sender_jid: str,
    remote_jid: str,
    message_id: str,
) -> BinaryNode | None:
    """Generates a reporting token binary node for a message."""
    if not message_secret:
        return None
        
    reporting_secret = hkdf(message_secret, 32, salt=b"", info=b"WhatsApp Reporting Token")
    
    content = _extract_reporting_token_content(message_bytes, REPORTING_FIELDS)
    if not content:
        return None
        
    reporting_token = hmac_sha256(reporting_secret, content)[:16]
    
    return BinaryNode(
        tag="reporting",
        attrs={},
        content=[
            BinaryNode(
                tag="reporting_token",
                attrs={"v": "2"},
                content=reporting_token,
            )
        ],
    )
