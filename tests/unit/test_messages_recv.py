from waton.client.messages_recv import classify_incoming_node
from waton.protocol.binary_node import BinaryNode

def test_classify_message_node() -> None:
    node = BinaryNode(tag="message", attrs={"id": "1"}, content=[])
    assert classify_incoming_node(node) == "message"
