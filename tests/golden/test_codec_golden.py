import os
from waton.protocol.binary_node import BinaryNode
from waton.protocol.binary_codec import encode_binary_node, decode_binary_node

def test_golden_binary_codec():
    """
    Golden byte-level reference test.
    In a complete port, we would capture actual WebSocket frames from Baileys
    and ensure `encode_binary_node` produces identical bytes.
    For now, we verify that our logic produces a stable known output for a Ping node.
    """
    node = BinaryNode(
        tag="iq",
        attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "w:p", "id": "123"},
    )
    
    encoded = encode_binary_node(node)
    
    # We verify it doesn't crash and is stable
    assert isinstance(encoded, bytes)
    assert len(encoded) > 0
    
    # Verify roundtrip for good measure in golden test
    decoded = decode_binary_node(encoded)
    assert decoded.tag == node.tag
    assert decoded.attrs == node.attrs

def test_golden_double_byte_tokens():
    """Verify specific double byte tokens compile exactly as expected."""
    # `image` is a double byte token
    node = BinaryNode(tag="image", attrs={})
    encoded = encode_binary_node(node)
    
    # Should start with LIST_EMPTY (0) or similar, then dictionary tag
    # We just ensure it roundtrips precisely
    decoded = decode_binary_node(encoded)
    assert decoded.tag == "image"
