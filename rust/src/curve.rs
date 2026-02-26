use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{clamp_integer, Scalar};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn generate_keypair() -> HashMap<String, Vec<u8>> {
    let mut rng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public_key = PublicKey::from(&secret);

    let mut map = HashMap::new();
    map.insert("private".to_string(), secret.to_bytes().to_vec());
    map.insert("public".to_string(), public_key.to_bytes().to_vec());
    map
}

pub fn shared_key(private_bytes: &[u8], public_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if private_bytes.len() != 32 || public_bytes.len() != 32 {
        return Err("Keys must be 32 bytes".to_string());
    }

    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(private_bytes);
    let secret = StaticSecret::from(priv_arr);

    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(public_bytes);
    let public_key = PublicKey::from(pub_arr);

    let shared_secret = secret.diffie_hellman(&public_key);
    Ok(shared_secret.to_bytes().to_vec())
}

fn hash_i_padding<const S: usize>(i: u128) -> [u8; S] {
    let mut padding = [0xffu8; S];
    let slice = (u128::MAX - i).to_le_bytes();
    for idx in 0..slice.len() {
        padding[idx] = slice[idx];
    }
    padding
}

fn calculate_xeddsa_keypair(private: &[u8; 32], sign: u8) -> ([u8; 32], [u8; 32]) {
    let clamped = clamp_integer(*private);
    let scalar_private_key = Scalar::from_bytes_mod_order(clamped);
    let point_public_key = EdwardsPoint::mul_base(&scalar_private_key);
    let compressed = point_public_key.compress().to_bytes();
    let sign_bit = (compressed[31] & 0x80) >> 7;

    if sign_bit == sign {
        (clamped, compressed)
    } else {
        let neg_scalar = (Scalar::ZERO - Scalar::from(1u8)) * scalar_private_key;
        let neg_point = EdwardsPoint::mul_base(&neg_scalar);
        (neg_scalar.to_bytes(), neg_point.compress().to_bytes())
    }
}

pub fn sign(private_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    if private_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".to_string());
    }

    let mut private = [0u8; 32];
    private.copy_from_slice(private_bytes);

    // XEdDSA signing flow used by Signal (and therefore WhatsApp/Baileys).
    let (private_key, public_key) = calculate_xeddsa_keypair(&private, 0);

    let mut rng = OsRng;
    let mut nonce = [0u8; 64];
    rng.fill_bytes(&mut nonce);

    let mut hasher = Sha512::new();
    hasher.update(hash_i_padding::<32>(1));
    hasher.update(private_key);
    hasher.update(message);
    hasher.update(nonce);
    let res: [u8; 64] = hasher.finalize().into();

    let res_scalar = Scalar::from_bytes_mod_order_wide(&res);
    let res_point = EdwardsPoint::mul_base(&res_scalar);
    let res_bytes = res_point.compress().to_bytes();

    let mut hasher = Sha512::new();
    hasher.update(res_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let hash: [u8; 64] = hasher.finalize().into();

    let hash_scalar = Scalar::from_bytes_mod_order_wide(&hash);
    let private_scalar = Scalar::from_bytes_mod_order(private_key);
    let s = res_scalar + hash_scalar * private_scalar;

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&res_bytes);
    signature[32..].copy_from_slice(&s.to_bytes());
    Ok(signature.to_vec())
}

pub fn verify(public_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> Result<bool, String> {
    if public_bytes.len() != 32 {
        return Err("Public key must be 32 bytes".to_string());
    }
    if signature_bytes.len() != 64 {
        return Err("Signature must be 64 bytes".to_string());
    }

    let mut montgomery_public = [0u8; 32];
    montgomery_public.copy_from_slice(public_bytes);

    // Convert X25519 Montgomery public key into Ed25519 key using sign=0 convention.
    let edwards_public = MontgomeryPoint(montgomery_public)
        .to_edwards(0)
        .ok_or_else(|| "Unusable or weak public key".to_string())?
        .compress()
        .to_bytes();

    let verifying_key =
        VerifyingKey::from_bytes(&edwards_public).map_err(|e| format!("Invalid public key: {}", e))?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| format!("Invalid signature format: {}", e))?;

    Ok(verifying_key.verify(message, &signature).is_ok())
}

