from waton.client.messages_recv import classify_incoming_node, decode_incoming_message_node
from waton.protocol.binary_node import BinaryNode
from waton.protocol.protobuf import WAProto_pb2 as wa_pb2
import pytest

def test_classify_message_node() -> None:
    node = BinaryNode(tag="message", attrs={"id": "1"}, content=[])
    assert classify_incoming_node(node) == "message"

@pytest.mark.asyncio
async def test_decrypt_and_normalize_enc_message(monkeypatch) -> None:
    # Fake repo
    class FakeRepo:
        async def decrypt_message_node(self, node: BinaryNode) -> bytes:
            msg = wa_pb2.Message()
            msg.conversation = "hi"
            return msg.SerializeToString()
    
    enc_node = BinaryNode(tag="message", attrs={}, content=[])
    event = await decode_incoming_message_node(enc_node, FakeRepo())
    assert event["type"] == "messages.upsert"
    assert event["message"]["text"] == "hi"
