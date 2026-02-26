use hkdf::Hkdf;
use sha2::Sha256;

pub fn hkdf_sha256(input: &[u8], length: usize, salt: &[u8], info: &[u8]) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input);
    let mut okm = vec![0u8; length];
    
    hk.expand(info, &mut okm)
        .map_err(|_| "HKDF expansion failed".to_string())?;
        
    Ok(okm)
}
