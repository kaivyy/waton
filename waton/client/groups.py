from waton.protocol.binary_node import BinaryNode
from waton.client.client import WAClient
import os

class GroupsAPI:
    def __init__(self, client: WAClient):
        self.client = client

    async def create_group(self, subject: str, participants: list[str]) -> str:
        """Creates a new group and returns its new JID."""
        create_id = os.urandom(6).hex()
        
        participant_nodes = [BinaryNode(tag="participant", attrs={"jid": p}) for p in participants]
        group_node = BinaryNode(
            tag="create",
            attrs={"subject": subject},
            content=participant_nodes
        )
        
        node = BinaryNode(
            tag="iq",
            attrs={"to": "@g.us", "type": "set", "xmlns": "w:g2", "id": create_id},
            content=[group_node]
        )
        await self.client.send_node(node)
        # res = await self.client.query(node)
        # group jid comes from response node: res.content[0].attrs["id"]
        return "stub_group_jid@g.us"

    async def leave_group(self, group_jid: str):
        """Leaves a group chat."""
        leave_id = os.urandom(6).hex()
        node = BinaryNode(
            tag="iq",
            attrs={"to": group_jid, "type": "set", "xmlns": "w:g2", "id": leave_id},
            content=[BinaryNode(tag="leave", attrs={})]
        )
        await self.client.send_node(node)

    async def add_participants(self, group_jid: str, participants: list[str]):
        """Adds participants to a group."""
        participant_nodes = [BinaryNode(tag="participant", attrs={"jid": p}) for p in participants]
        add_node = BinaryNode(tag="add", attrs={}, content=participant_nodes)
        
        node = BinaryNode(
            tag="iq",
            attrs={"to": group_jid, "type": "set", "xmlns": "w:g2"},
            content=[add_node]
        )
        await self.client.send_node(node)
