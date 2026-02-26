import math
import io
import struct
import zlib
from .binary_node import BinaryNode
from .constants import Tags, TOKEN_MAP, SINGLE_BYTE_TOKENS, DOUBLE_BYTE_TOKENS

def encode_binary_node(node: BinaryNode) -> bytes:
    # Non-compressed WA binary payloads are prefixed with 0x00.
    buf = bytearray([0])
    _encode_node(node, buf)
    return bytes(buf)

def _encode_node(node: BinaryNode, buf: bytearray):
    tag = node.tag
    attrs = node.attrs or {}
    content = node.content

    # Count actual attributes, skip None
    valid_attrs = {k: v for k, v in attrs.items() if v is not None}
    
    # List size: tag + 2 * len(attrs) + (1 if content else 0)
    has_content = 1 if content is not None else 0
    list_size = 1 + 2 * len(valid_attrs) + has_content

    _write_list_start(list_size, buf)
    _write_string(tag, buf)

    for k, v in valid_attrs.items():
        _write_string(k, buf)
        _write_string(v, buf)

    if content is not None:
        if isinstance(content, str):
            _write_string(content, buf)
        elif isinstance(content, (bytes, bytearray)):
            _write_bytes(content, buf)
        elif isinstance(content, list):
            _write_list_start(len(content), buf)
            for child in content:
                _encode_node(child, buf)
        else:
            raise ValueError(f"Invalid content type: {type(content)}")

def _write_list_start(size: int, buf: bytearray):
    if size == 0:
        buf.append(Tags.LIST_EMPTY)
    elif size < 256:
        buf.append(Tags.LIST_8)
        buf.append(size)
    elif size < 65536:
        buf.append(Tags.LIST_16)
        buf.extend(struct.pack(">H", size))
    else:
        raise ValueError(f"List too large: {size}")

def _write_bytes(data: bytes | bytearray, buf: bytearray):
    length = len(data)
    if length >= 4294967296:
        raise ValueError("Byte string too long")

    if length < 256:
        buf.append(Tags.BINARY_8)
        buf.append(length)
    elif length < 1048576:
        buf.append(Tags.BINARY_20)
        buf.append((length >> 16) & 0xFF)
        buf.extend(struct.pack(">H", length & 0xFFFF))
    else:
        buf.append(Tags.BINARY_32)
        buf.extend(struct.pack(">I", length))
    
    buf.extend(data)

def _write_string(s: str, buf: bytearray):
    if not isinstance(s, str):
        s = str(s)
    
    if s == "c.us":
        s = "s.whatsapp.net"
    
    # Try token
    token_info = TOKEN_MAP.get(s)
    if token_info:
        if token_info['dict'] == 0:
            buf.append(token_info['index'])
        else:
            buf.append(Tags.DICTIONARY_0 + token_info['dict'] - 1)
            buf.append(token_info['index'])
        return

    # Try JID
    jid_idx = s.find("@")
    if jid_idx != -1:
        user_part = s[:jid_idx]
        server = s[jid_idx+1:]
        # Check for device JID: "user:device@server"
        colon_idx = user_part.find(":")
        if colon_idx != -1 and user_part[colon_idx+1:].isdigit():
            user = user_part[:colon_idx]
            device = int(user_part[colon_idx+1:])
            _write_ad_jid(user, device, server, buf)
        else:
            _write_jid(user_part, server, buf)
        return

    # Fallback to UTF-8
    _write_bytes(s.encode('utf-8'), buf)

_DOMAIN_TYPE_MAP = {
    "s.whatsapp.net": 0,
    "lid": 1,
    "hosted": 2,
    "hosted.lid": 3,
}

def _write_ad_jid(user: str, device: int, server: str, buf: bytearray):
    """Write a device-specific JID using AD_JID format (tag 247)."""
    buf.append(Tags.AD_JID)
    domain_type = _DOMAIN_TYPE_MAP.get(server, 0)
    buf.append(domain_type)
    buf.append(device)
    _write_string(user, buf)

def _write_jid(user: str, server: str, buf: bytearray):
    buf.append(Tags.JID_PAIR)
    if not user:
        buf.append(Tags.LIST_EMPTY)
    else:
        _write_string(user, buf)
    _write_string(server, buf)


# --- DECODE ---

def decode_binary_node(data: bytes) -> BinaryNode:
    if not data:
        raise ValueError("Empty binary payload")
    if data[0] & 0x02:
        payload = zlib.decompress(data[1:])
    else:
        payload = data[1:]
    return _decode_node(io.BytesIO(payload))

def _decode_node(stream: io.BytesIO) -> BinaryNode:
    list_size = _read_list_size(stream)
    if list_size == 0:
        raise ValueError("Invalid node: list size 0")

    tag = _read_string(stream)
    attrs = {}

    for _ in range((list_size - 1) // 2):
        key = _read_string(stream)
        val = _read_string(stream)
        attrs[key] = val

    content = None
    if list_size % 2 == 0:
        # has content
        val = stream.read(1)
        if not val:
            raise EOFError("EOF reading content")
        tag_val = val[0]
        
        if tag_val in (Tags.LIST_EMPTY, Tags.LIST_8, Tags.LIST_16):
            stream.seek(-1, io.SEEK_CUR)
            content_size = _read_list_size(stream)
            content = []
            for _ in range(content_size):
                content.append(_decode_node(stream))
        elif tag_val in (Tags.BINARY_8, Tags.BINARY_20, Tags.BINARY_32):
            stream.seek(-1, io.SEEK_CUR)
            content = _read_bytes(stream)
        else:
            stream.seek(-1, io.SEEK_CUR)
            content = _read_string(stream)

    return BinaryNode(tag=tag, attrs=attrs, content=content)

def _read_list_size(stream: io.BytesIO) -> int:
    value = stream.read(1)
    if not value:
        raise EOFError("EOF reading list size")
    b = value[0]
    if b == Tags.LIST_EMPTY:
        return 0
    if b == Tags.LIST_8:
        return stream.read(1)[0]
    if b == Tags.LIST_16:
        return struct.unpack(">H", stream.read(2))[0]
    raise ValueError(f"Invalid list size tag: {b}")

def _read_bytes(stream: io.BytesIO) -> bytes:
    value = stream.read(1)
    if not value:
        raise EOFError("EOF reading bytes tag")
    b = value[0]
    if b == Tags.BINARY_8:
        length_raw = stream.read(1)
        if not length_raw:
            raise EOFError("EOF reading BINARY_8 length")
        length = length_raw[0]
        return stream.read(length)
    if b == Tags.BINARY_20:
        length = (stream.read(1)[0] << 16) | struct.unpack(">H", stream.read(2))[0]
        return stream.read(length)
    if b == Tags.BINARY_32:
        length = struct.unpack(">I", stream.read(4))[0]
        return stream.read(length)
    raise ValueError(f"Invalid bytes tag: {b}")

def _read_int(stream: io.BytesIO, n: int) -> int:
    data = stream.read(n)
    if len(data) != n:
        raise EOFError("EOF reading int")
    out = 0
    for value in data:
        out = (out << 8) | value
    return out

def _read_int20(stream: io.BytesIO) -> int:
    data = stream.read(3)
    if len(data) != 3:
        raise EOFError("EOF reading int20")
    return ((data[0] & 0x0F) << 16) | (data[1] << 8) | data[2]

def _unpack_hex(value: int) -> int:
    if 0 <= value < 10:
        return ord("0") + value
    if 10 <= value < 16:
        return ord("A") + value - 10
    raise ValueError(f"Invalid hex nibble: {value}")

def _unpack_nibble(value: int) -> int:
    if 0 <= value <= 9:
        return ord("0") + value
    if value == 10:
        return ord("-")
    if value == 11:
        return ord(".")
    if value == 15:
        return 0
    raise ValueError(f"Invalid nibble: {value}")

def _read_packed8(stream: io.BytesIO, tag: int) -> str:
    start_raw = stream.read(1)
    if not start_raw:
        raise EOFError("EOF reading packed8 length")
    start = start_raw[0]
    out: list[int] = []
    unpack = _unpack_nibble if tag == Tags.NIBBLE_8 else _unpack_hex
    for _ in range(start & 0x7F):
        cur_raw = stream.read(1)
        if not cur_raw:
            raise EOFError("EOF reading packed8 payload")
        cur = cur_raw[0]
        out.append(unpack((cur & 0xF0) >> 4))
        out.append(unpack(cur & 0x0F))
    if start >> 7:
        out = out[:-1]
    return bytes(out).replace(b"\x00", b"").decode("utf-8", errors="ignore")

def _read_ad_jid(stream: io.BytesIO) -> str:
    raw_domain = stream.read(1)
    device_raw = stream.read(1)
    if not raw_domain or not device_raw:
        raise EOFError("EOF reading AD_JID")
    domain_type = raw_domain[0]
    device = device_raw[0]
    user_tag = stream.read(1)
    if not user_tag:
        raise EOFError("EOF reading AD_JID user tag")
    user = _read_string_from_tag(stream, user_tag[0])
    server = "s.whatsapp.net"
    if domain_type == 1:
        server = "lid"
    elif domain_type == 2:
        server = "hosted"
    elif domain_type == 3:
        server = "hosted.lid"
    return f"{user}:{device}@{server}"

def _read_fb_jid(stream: io.BytesIO) -> str:
    user_tag = stream.read(1)
    if not user_tag:
        raise EOFError("EOF reading FB_JID user tag")
    user = _read_string_from_tag(stream, user_tag[0])
    device = _read_int(stream, 2)
    server_tag = stream.read(1)
    if not server_tag:
        raise EOFError("EOF reading FB_JID server tag")
    server = _read_string_from_tag(stream, server_tag[0])
    return f"{user}:{device}@{server}"

def _read_interop_jid(stream: io.BytesIO) -> str:
    user_tag = stream.read(1)
    if not user_tag:
        raise EOFError("EOF reading INTEROP_JID user tag")
    user = _read_string_from_tag(stream, user_tag[0])
    device = _read_int(stream, 2)
    integrator = _read_int(stream, 2)
    server = "interop"
    before = stream.tell()
    maybe_server_tag = stream.read(1)
    if maybe_server_tag:
        try:
            server = _read_string_from_tag(stream, maybe_server_tag[0])
        except Exception:
            stream.seek(before)
    return f"{integrator}-{user}:{device}@{server}"

def _read_string_from_tag(stream: io.BytesIO, b: int) -> str:
    if 0 < b < len(SINGLE_BYTE_TOKENS):
        token = SINGLE_BYTE_TOKENS[b]
        return token or ""
    if Tags.DICTIONARY_0 <= b <= Tags.DICTIONARY_3:
        idx_raw = stream.read(1)
        if not idx_raw:
            raise EOFError("EOF reading double token index")
        idx = idx_raw[0]
        dict_idx = b - Tags.DICTIONARY_0
        token = DOUBLE_BYTE_TOKENS[dict_idx][idx]
        if token is None:
            raise ValueError(f"Empty double byte token: {dict_idx},{idx}")
        return token
    if b == Tags.LIST_EMPTY:
        return ""
    if b == Tags.BINARY_8:
        length_raw = stream.read(1)
        if not length_raw:
            raise EOFError("EOF reading BINARY_8 length")
        return stream.read(length_raw[0]).decode("utf-8")
    if b == Tags.BINARY_20:
        return stream.read(_read_int20(stream)).decode("utf-8")
    if b == Tags.BINARY_32:
        return stream.read(_read_int(stream, 4)).decode("utf-8")
    if b == Tags.JID_PAIR:
        user_tag = stream.read(1)
        if not user_tag:
            raise EOFError("EOF reading JID_PAIR user tag")
        user = _read_string_from_tag(stream, user_tag[0])
        server_tag = stream.read(1)
        if not server_tag:
            raise EOFError("EOF reading JID_PAIR server tag")
        server = _read_string_from_tag(stream, server_tag[0])
        if user == "" or user is None:
            return server
        return f"{user}@{server}"
    if b == Tags.AD_JID:
        return _read_ad_jid(stream)
    if b == Tags.FB_JID:
        return _read_fb_jid(stream)
    if b == Tags.INTEROP_JID:
        return _read_interop_jid(stream)
    if b in (Tags.NIBBLE_8, Tags.HEX_8):
        return _read_packed8(stream, b)
    raise ValueError(f"Invalid string tag: {b}")

def _read_string(stream: io.BytesIO) -> str:
    value = stream.read(1)
    if not value:
        raise EOFError("EOF reading string tag")
    return _read_string_from_tag(stream, value[0])
