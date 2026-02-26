use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| format!("HMAC key Error: {}", e))?;
        
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
