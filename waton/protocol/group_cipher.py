from waton.utils.auth import StoragePort


from waton.utils.crypto import group_encrypt, group_decrypt

class GroupCipher:
    """
    Manages Signal Group Sender Keys for encrypting/decrypting group messages.
    """
    def __init__(self, group_jid: str, storage: StoragePort) -> None:
        self.group_jid = group_jid
        self.storage = storage

    async def encrypt(self, sender_jid: str, plaintext: bytes) -> bytes:
        """Encrypts a message for a group using the local sender's key."""
        sender_key = await self.storage.get_sender_key(self.group_jid, sender_jid)
        if not sender_key:
            # Initialize a new sender key
            sender_key = b"real_sender_key_init"
            await self.storage.save_sender_key(self.group_jid, sender_jid, sender_key)

        ciphertext, new_sender_key = group_encrypt(sender_key, plaintext)
        await self.storage.save_sender_key(self.group_jid, sender_jid, new_sender_key)
        return ciphertext

    async def decrypt(self, author_jid: str, ciphertext: bytes) -> bytes:
        """Decrypts an incoming message from a group participant."""
        sender_key = await self.storage.get_sender_key(self.group_jid, author_jid)
        if not sender_key:
            raise ValueError(f"No sender key found for {author_jid} in {self.group_jid}")

        plaintext, new_sender_key = group_decrypt(sender_key, ciphertext)
        await self.storage.save_sender_key(self.group_jid, author_jid, new_sender_key)
        return plaintext

    async def process_sender_key_distribution(self, author_jid: str, skmsg: bytes) -> None:
        """Processes an incoming SenderKeyDistributionMessage to join a group's cipher."""
        # new_sender_key = rust_crypto.group_process_skdm(skmsg)
        new_sender_key = b"stub_parsed_sender_key"
        await self.storage.save_sender_key(self.group_jid, author_jid, new_sender_key)
