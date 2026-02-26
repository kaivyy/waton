use std::collections::HashMap;

use async_trait::async_trait;
use futures::executor::block_on;
use rand09::rng;
use wa_rs_libsignal::protocol::error::Result as SignalResult;
use wa_rs_libsignal::protocol::{
    CiphertextMessageType, Direction, IdentityChange, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, PreKeyBundle, PreKeyId, PrivateKey, ProtocolAddress, PublicKey, SessionRecord,
    SessionStore, SignalProtocolError, SignedPreKeyId, UsePQRatchet, message_encrypt, process_prekey_bundle,
    message_decrypt, message_decrypt_prekey, PreKeySignalMessage, SignalMessage,
};

#[derive(Debug)]
pub struct EncryptedPayload {
    pub msg_type: String,
    pub ciphertext: Vec<u8>,
    pub session: Vec<u8>,
}

struct OneSessionStore {
    address: ProtocolAddress,
    session: Option<SessionRecord>,
}

impl OneSessionStore {
    fn new(address: ProtocolAddress, serialized_session: Option<&[u8]>) -> Result<Self, String> {
        let session = match serialized_session {
            Some(bytes) if !bytes.is_empty() => Some(
                SessionRecord::deserialize(bytes)
                    .map_err(|err| format!("invalid serialized session: {err}"))?,
            ),
            _ => None,
        };
        Ok(Self { address, session })
    }

    fn serialize_session(&self) -> Result<Vec<u8>, String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| "missing session after signal operation".to_string())?;
        session
            .serialize()
            .map_err(|err| format!("failed to serialize session: {err}"))
    }
}

#[async_trait]
impl SessionStore for OneSessionStore {
    async fn load_session(&self, address: &ProtocolAddress) -> SignalResult<Option<SessionRecord>> {
        if address == &self.address {
            Ok(self.session.clone())
        } else {
            Ok(None)
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> SignalResult<()> {
        if address != &self.address {
            return Err(SignalProtocolError::InvalidArgument(
                "attempted to store session for unexpected address".to_string(),
            ));
        }
        self.session = Some(record.clone());
        Ok(())
    }
}

struct OneIdentityStore {
    identity_pair: IdentityKeyPair,
    registration_id: u32,
    known: HashMap<ProtocolAddress, IdentityKey>,
}

impl OneIdentityStore {
    fn new(identity_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity_pair,
            registration_id,
            known: HashMap::new(),
        }
    }
}

#[async_trait]
impl IdentityKeyStore for OneIdentityStore {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        Ok(self.identity_pair.clone())
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        let changed = self.known.get(address).is_some_and(|current| current != identity);
        self.known.insert(address.clone(), *identity);
        Ok(IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> SignalResult<bool> {
        Ok(self.known.get(address).is_none_or(|current| current == identity))
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SignalResult<Option<IdentityKey>> {
        Ok(self.known.get(address).copied())
    }
}

fn signal_address(name: &str, device: u32) -> ProtocolAddress {
    ProtocolAddress::new(name.to_string(), device.into())
}

fn to_identity_keypair(identity_private: &[u8]) -> Result<IdentityKeyPair, String> {
    let private_key = PrivateKey::deserialize(identity_private)
        .map_err(|err| format!("invalid local identity private key: {err}"))?;
    IdentityKeyPair::try_from(private_key)
        .map_err(|err| format!("failed to derive identity keypair: {err}"))
}

fn ensure_signal_public_key(raw: &[u8]) -> Result<Vec<u8>, String> {
    match raw.len() {
        33 => Ok(raw.to_vec()),
        32 => {
            let mut prefixed = Vec::with_capacity(33);
            prefixed.push(0x05);
            prefixed.extend_from_slice(raw);
            Ok(prefixed)
        }
        other => Err(format!("unexpected public key length: {other}")),
    }
}

fn decode_public_key(raw: &[u8]) -> Result<PublicKey, String> {
    let bytes = ensure_signal_public_key(raw)?;
    PublicKey::deserialize(&bytes).map_err(|err| format!("invalid public key: {err}"))
}

fn decode_identity_key(raw: &[u8]) -> Result<IdentityKey, String> {
    let bytes = ensure_signal_public_key(raw)?;
    IdentityKey::decode(&bytes).map_err(|err| format!("invalid identity key: {err}"))
}

#[expect(clippy::too_many_arguments)]
pub fn process_prekey_bundle_for_session(
    session: Option<&[u8]>,
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    remote_registration_id: u32,
    remote_identity_key: &[u8],
    signed_prekey_id: u32,
    signed_prekey_public: &[u8],
    signed_prekey_signature: &[u8],
    prekey_id: Option<u32>,
    prekey_public: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let address = signal_address(remote_name, remote_device);
    let identity_pair = to_identity_keypair(identity_private)?;
    let mut session_store = OneSessionStore::new(address.clone(), session)?;
    let mut identity_store = OneIdentityStore::new(identity_pair, registration_id);

    let remote_identity = decode_identity_key(remote_identity_key)?;
    let remote_signed_prekey = decode_public_key(signed_prekey_public)?;
    let remote_prekey = match (prekey_id, prekey_public) {
        (Some(id), Some(key)) => Some((PreKeyId::from(id), decode_public_key(key)?)),
        (Some(_), None) => {
            return Err("prekey_id provided without prekey_public".to_string());
        }
        (None, Some(_)) => {
            return Err("prekey_public provided without prekey_id".to_string());
        }
        (None, None) => None,
    };

    let bundle = PreKeyBundle::new(
        remote_registration_id,
        remote_device.into(),
        remote_prekey,
        SignedPreKeyId::from(signed_prekey_id),
        remote_signed_prekey,
        signed_prekey_signature.to_vec(),
        remote_identity,
    )
    .map_err(|err| format!("failed to build prekey bundle: {err}"))?;

    let mut csprng = rng();
    block_on(process_prekey_bundle(
        &address,
        &mut session_store,
        &mut identity_store,
        &bundle,
        &mut csprng,
        UsePQRatchet::No,
    ))
    .map_err(|err| format!("failed to process prekey bundle: {err}"))?;

    session_store.serialize_session()
}

pub fn encrypt_with_session(
    session: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    plaintext: &[u8],
) -> Result<EncryptedPayload, String> {
    let address = signal_address(remote_name, remote_device);
    let identity_pair = to_identity_keypair(identity_private)?;
    let mut session_store = OneSessionStore::new(address.clone(), Some(session))?;
    let mut identity_store = OneIdentityStore::new(identity_pair, registration_id);

    let encrypted = block_on(message_encrypt(
        plaintext,
        &address,
        &mut session_store,
        &mut identity_store,
    ))
    .map_err(|err| format!("signal encryption failed: {err}"))?;

    let msg_type = match encrypted.message_type() {
        CiphertextMessageType::Whisper => "msg".to_string(),
        CiphertextMessageType::PreKey => "pkmsg".to_string(),
        other => {
            return Err(format!(
                "unsupported ciphertext message type for whatsapp relay: {:?}",
                other
            ));
        }
    };

    Ok(EncryptedPayload {
        msg_type,
        ciphertext: encrypted.serialize().to_vec(),
        session: session_store.serialize_session()?,
    })
}

pub fn decrypt_with_session_prekey(
    session: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    ciphertext: &[u8],
) -> Result<EncryptedPayload, String> {
    let address = signal_address(remote_name, remote_device);
    let identity_pair = to_identity_keypair(identity_private)?;
    let mut session_store = OneSessionStore::new(address.clone(), Some(session))?;
    let mut identity_store = OneIdentityStore::new(identity_pair, registration_id);

    let message = PreKeySignalMessage::deserialize(ciphertext)
        .map_err(|e| format!("invalid prekey message: {}", e))?;

    let plaintext = block_on(message_decrypt_prekey(
        &message,
        &address,
        &mut session_store,
        &mut identity_store,
    ))
    .map_err(|e| format!("signal decryption failed: {}", e))?;

    Ok(EncryptedPayload {
        msg_type: "plaintext".to_string(),
        ciphertext: plaintext,
        session: session_store.serialize_session()?,
    })
}

pub fn decrypt_with_session_whisper(
    session: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    ciphertext: &[u8],
) -> Result<EncryptedPayload, String> {
    let address = signal_address(remote_name, remote_device);
    let identity_pair = to_identity_keypair(identity_private)?;
    let mut session_store = OneSessionStore::new(address.clone(), Some(session))?;
    let mut identity_store = OneIdentityStore::new(identity_pair, registration_id);

    let message = SignalMessage::deserialize(ciphertext)
        .map_err(|e| format!("invalid whisper message: {}", e))?;

    let plaintext = block_on(message_decrypt(
        &message,
        &address,
        &mut session_store,
        &mut identity_store,
    ))
    .map_err(|e| format!("signal decryption failed: {}", e))?;

    Ok(EncryptedPayload {
        msg_type: "plaintext".to_string(),
        ciphertext: plaintext,
        session: session_store.serialize_session()?,
    })
}
