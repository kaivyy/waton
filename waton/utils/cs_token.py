from __future__ import annotations

from waton.core.jid import jid_normalized_user
from waton.protocol.binary_node import BinaryNode
from waton.utils.crypto import hmac_sha256

class CSTokenManager:
    def __init__(self) -> None:
        self.nct_salt: bytes | None = None

    def set_nct_salt(self, salt: bytes) -> None:
        """Sets the NCT salt used for CSToken derivation."""
        self.nct_salt = salt

    def get_nct_salt(self) -> bytes | None:
        """Gets the NCT salt."""
        return self.nct_salt

    def generate_cs_token(self, recipient_lid: str) -> bytes | None:
        """Generates a CS token for a recipient LID."""
        if not self.nct_salt:
            return None
            
        lid_user = jid_normalized_user(recipient_lid)
        if not lid_user:
            # fallback to raw string if jid_normalized_user returns empty
            lid_user = recipient_lid
            
        return hmac_sha256(self.nct_salt, lid_user.encode("utf-8"))

    @staticmethod
    def build_cs_token_node(token: bytes) -> BinaryNode:
        """Builds a cstoken XML node."""
        return BinaryNode(tag="cstoken", attrs={}, content=token)

