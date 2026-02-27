import zlib

from waton.protocol.binary_node import BinaryNode
from waton.protocol.binary_codec import encode_binary_node, decode_binary_node

def test_simple_node_roundtrip():
    node = BinaryNode(tag="iq", attrs={"type": "get", "to": "s.whatsapp.net"})
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.tag == node.tag
    assert decoded.attrs == node.attrs

def test_node_with_content():
    node = BinaryNode(tag="message", attrs={"id": "123"}, content=b"hello")
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.content == b"hello"
    assert decoded.attrs["id"] == "123"

def test_nested_nodes():
    child = BinaryNode(tag="ping", attrs={})
    node = BinaryNode(tag="iq", attrs={"type": "get"}, content=[child])
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert len(decoded.content) == 1
    assert decoded.content[0].tag == "ping"

def test_jid_encoding():
    node = BinaryNode(tag="iq", attrs={"to": "123@s.whatsapp.net"})
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.attrs["to"] == "123@s.whatsapp.net"

def test_single_byte_token():
    node = BinaryNode(tag="read-self", attrs={})
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.tag == "read-self"

def test_double_byte_token():
    # 'reject' is in DBT
    node = BinaryNode(tag="reject", attrs={})
    encoded = encode_binary_node(node)
    decoded = decode_binary_node(encoded)
    assert decoded.tag == "reject"


def test_prefix_and_compressed_decode() -> None:
    node = BinaryNode(tag="iq", attrs={"type": "get"})
    encoded = encode_binary_node(node)
    assert encoded[0] == 0

    compressed = bytes([0x02]) + zlib.compress(encoded[1:])
    decoded = decode_binary_node(compressed)
    assert decoded.tag == "iq"
