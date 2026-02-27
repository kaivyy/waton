from __future__ import annotations

from typing import TYPE_CHECKING, Any

from waton.core.jid import jid_decode
from waton.utils.crypto import (
    generate_keypair,
    signal_process_prekey_bundle,
    signal_session_encrypt,
    signal_session_decrypt_prekey,
    signal_session_decrypt_whisper,
)

if TYPE_CHECKING:
    from waton.utils.auth import AuthCreds, StoragePort

class SignalRepository:
    """
    Manages E2E Signal protocol states (identities, prekeys, sessions).
    Interacts directly with the StoragePort to read/write persistent keys.
    """
    def __init__(self, creds: AuthCreds, storage: StoragePort) -> None:
        self.creds = creds
        self.storage = storage
        self._domain_suffix = {
            "s.whatsapp.net": "",
            "lid": "_1",
            "hosted": "_2",
            "hosted.lid": "_3",
        }

    def _session_key(self, jid: str) -> str:
        """Normalize JID to consistent session key (signal address format).

        Ensures '628xxx@s.whatsapp.net' and '628xxx:0@s.whatsapp.net'
        both map to the same key '628xxx.0'.
        """
        name, device = self.jid_to_signal_address(jid)
        return f"{name}.{device}"

    async def get_session(self, jid: str) -> bytes | None:
        return await self.storage.get_session(self._session_key(jid))

    async def save_session(self, jid: str, session_data: bytes) -> None:
        await self.storage.save_session(self._session_key(jid), session_data)

    async def get_prekey(self, key_id: int) -> bytes | None:
        return await self.storage.get_prekey(key_id)

    async def generate_prekeys(self, count: int) -> list[dict[str, Any]]:
        """Generates new pre-keys for upload to server."""
        start_id = self.creds.next_pre_key_id
        new_keys = []
        for i in range(count):
            kp = generate_keypair()
            # A real implementation serializes the prekey to libsignal format
            # Here we just mock the payload that WA needs
            key_id = start_id + i
            new_keys.append({
                "keyId": key_id,
                "keyPair": kp
            })
            await self.storage.save_prekey(key_id, kp["private"])

        self.creds.next_pre_key_id += count
        await self.storage.save_creds(self.creds)
        return new_keys

    def jid_to_signal_address(self, jid: str) -> tuple[str, int]:
        decoded = jid_decode(jid)
        if not decoded or not decoded.user:
            raise ValueError(f"invalid jid for signal address: {jid}")
        suffix = self._domain_suffix.get(decoded.server, f"_{decoded.server}")
        name = decoded.user + suffix
        device = decoded.device if decoded.device is not None else 0
        return name, device

    async def inject_session_from_prekey_bundle(
        self,
        jid: str,
        *,
        registration_id: int,
        identity_key: bytes,
        signed_prekey_id: int,
        signed_prekey_public: bytes,
        signed_prekey_signature: bytes,
        prekey_id: int | None,
        prekey_public: bytes | None,
    ) -> None:
        signal_name, signal_device = self.jid_to_signal_address(jid)
        existing = await self.get_session(jid)
        session = signal_process_prekey_bundle(
            existing,
            self.creds.signed_identity_key["private"],
            int(self.creds.registration_id),
            signal_name,
            int(signal_device),
            int(registration_id),
            identity_key,
            int(signed_prekey_id),
            signed_prekey_public,
            signed_prekey_signature,
            int(prekey_id) if prekey_id is not None else None,
            prekey_public,
        )
        await self.save_session(jid, session)

    async def decrypt_message(self, jid: str, type_str: str, ciphertext: bytes) -> bytes:
        """
        Decrypts an incoming P2P message.
        `type_str` is either 'pkmsg' or 'msg'.
        """
        signal_name, signal_device = self.jid_to_signal_address(jid)
        session = await self.get_session(jid)
        
        if type_str == "pkmsg":
            # parse the protobuf to get prekey_id and signed_prekey_id without WAProto
            # The signal ciphertext starts with a version byte (typically 0x33 for version 3).
            # The protobuf follows.
            data = ciphertext[1:]
            
            p_id = None
            sp_id = None
            i = 0
            while i < len(data):
                if i >= len(data): break
                tag_wire = data[i]
                i += 1
                tag = tag_wire >> 3
                wire_type = tag_wire & 7
                
                if wire_type == 0:
                    val = 0
                    shift = 0
                    while i < len(data):
                        b = data[i]
                        i += 1
                        val |= (b & 0x7f) << shift
                        shift += 7
                        if not (b & 0x80):
                            break
                    if tag == 1:
                        p_id = val
                    elif tag == 2:
                        sp_id = val
                elif wire_type == 2:
                    length = 0
                    shift = 0
                    while i < len(data):
                        b = data[i]
                        i += 1
                        length |= (b & 0x7f) << shift
                        shift += 7
                        if not (b & 0x80):
                            break
                    i += length
                elif wire_type == 1:
                    i += 8
                elif wire_type == 5:
                    i += 4
                else:
                    break
                    
                # We can stop early if we have both, but preKeyId (tag 1) is optional.
                # Usually signedPreKeyId (tag 2) is present.
                if sp_id is not None and tag > 2:
                    break
            
            prekey_id = p_id
            signed_prekey_id = sp_id if sp_id is not None else 0
            
            prekey_private = None
            if prekey_id is not None:
                prekey_private = await self.get_prekey(prekey_id)
                if not prekey_private:
                    # Missing prekey, backend might still succeed if it was already processed
                    pass

            # Our signed prekey
            signed_prekey_private = self.creds.signed_pre_key["keyPair"]["private"]
            
            safe_session = session or b""
            
            res = signal_session_decrypt_prekey(
                session=safe_session,
                identity_private=self.creds.signed_identity_key["private"],
                registration_id=int(self.creds.registration_id),
                remote_name=signal_name,
                remote_device=int(signal_device),
                prekey_id=prekey_id,
                prekey_private=prekey_private,
                signed_prekey_id=int(signed_prekey_id),
                signed_prekey_private=signed_prekey_private,
                ciphertext=ciphertext,
            )
            
            # update session
            await self.save_session(jid, res["session"])
            return res["ciphertext"]

        elif type_str == "msg":
            if not session:
                raise ValueError(f"No active session for {jid}, cannot decrypt 'msg'")
            
            res = signal_session_decrypt_whisper(
                session=session,
                identity_private=self.creds.signed_identity_key["private"],
                registration_id=int(self.creds.registration_id),
                remote_name=signal_name,
                remote_device=int(signal_device),
                ciphertext=ciphertext,
            )
            
            await self.save_session(jid, res["session"])
            return res["ciphertext"]
            
        else:
            raise ValueError(f"Unknown message type: {type_str}")

    async def encrypt_message(self, jid: str, plaintext: bytes) -> tuple[str, bytes]:
        """
        Encrypts an outgoing P2P message.
        Returns (type_str, ciphertext).
        """
        session = await self.get_session(jid)
        if not session:
            raise ValueError(f"No session found for {jid}. Must fetch their prekeys first.")
        signal_name, signal_device = self.jid_to_signal_address(jid)
        msg_type, ciphertext, new_session = signal_session_encrypt(
            session,
            self.creds.signed_identity_key["private"],
            int(self.creds.registration_id),
            signal_name,
            int(signal_device),
            plaintext,
        )
        await self.save_session(jid, new_session)
        return msg_type, ciphertext
