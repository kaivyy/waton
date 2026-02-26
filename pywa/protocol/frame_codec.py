import struct
from pywa.protocol.binary_node import BinaryNode
from pywa.protocol.binary_codec import encode_binary_node, decode_binary_node

def encode_frame(data: bytes) -> bytes:
    """Packs raw bytes with a 3-byte length prefix (WhatsApp transport format)."""
    length = len(data)
    # 24-bit length
    header = bytearray(3)
    header[0] = (length >> 16) & 0xFF
    header[1] = (length >> 8) & 0xFF
    header[2] = length & 0xFF
    return bytes(header) + data

def decode_frame_length(header: bytes) -> int:
    """Extracts length from a 3-byte header."""
    if len(header) != 3:
        raise ValueError("Header must be exactly 3 bytes")
    return (header[0] << 16) | (header[1] << 8) | header[2]

def encode_payload_frame(node: BinaryNode) -> bytes:
    """Encodes a node and wraps it in a WA frame."""
    payload = encode_binary_node(node)
    # WA compressed frame bit 1 in header if compressed, but usually we just send plain binary
    return encode_frame(payload)

def decode_payload_frame(payload: bytes) -> BinaryNode:
    """Decodes a plain WA frame payload into a binary node."""
    # Ignore the first dummy bytes if needed, but normally raw payload is just decoded
    return decode_binary_node(payload)
