from waton.protocol.binary_node import BinaryNode
from waton.protocol.signal_repo import SignalRepository
from waton.protocol.protobuf import WAProto_pb2 as wa_pb2

def _unpad_random_max16(plaintext: bytes) -> bytes:
    # MVP unpad for test logic
    return plaintext

def classify_incoming_node(node: BinaryNode) -> str:
    if node.tag == "message":
        return "message"
    if node.tag == "receipt":
        return "receipt"
    if node.tag == "notification":
        return "notification"
    return "other"

async def decode_incoming_message_node(node: BinaryNode, signal_repo: SignalRepository) -> dict:
    plaintext = await signal_repo.decrypt_message_node(node)
    parsed = wa_pb2.Message()
    parsed.ParseFromString(_unpad_random_max16(plaintext))
    return {"type": "messages.upsert", "message": {"text": parsed.conversation}}
