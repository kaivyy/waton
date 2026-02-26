use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use cbc::{Decryptor, Encryptor};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn aes_gcm_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid AES-GCM key length".to_string())?;
    if iv.len() != 12 {
        return Err("AES-GCM IV must be 12 bytes".to_string());
    }
    let nonce = Nonce::from_slice(iv);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| format!("Encryption error: {:?}", e))
}

pub fn aes_gcm_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid AES-GCM key length".to_string())?;
    if iv.len() != 12 {
        return Err("AES-GCM IV must be 12 bytes".to_string());
    }
    let nonce = Nonce::from_slice(iv);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| format!("Decryption error: {:?}", e))
}

pub fn aes_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|_| "Invalid AES-CBC key or IV length".to_string())
        .map(|cipher| cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|_| "Invalid AES-CBC key or IV length".to_string())?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "Invalid AES-CBC ciphertext or padding".to_string())
}
