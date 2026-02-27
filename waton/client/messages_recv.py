from waton.protocol.binary_node import BinaryNode

def classify_incoming_node(node: BinaryNode) -> str:
    if node.tag == "message":
        return "message"
    if node.tag == "receipt":
        return "receipt"
    if node.tag == "notification":
        return "notification"
    return "other"
