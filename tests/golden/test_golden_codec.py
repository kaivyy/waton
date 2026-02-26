from pywa.protocol.binary_codec import decode_binary_node, encode_binary_node
from pywa.protocol.binary_node import BinaryNode


def test_golden_codec_alias() -> None:
    node = BinaryNode(
        tag="iq",
        attrs={"to": "s.whatsapp.net", "type": "get", "xmlns": "w:p", "id": "golden-1"},
    )
    payload = encode_binary_node(node)
    decoded = decode_binary_node(payload)
    assert decoded.tag == node.tag
    assert decoded.attrs == node.attrs
