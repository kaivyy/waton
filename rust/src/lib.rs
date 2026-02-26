use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

mod aes_gcm;
mod curve;
mod hkdf_utils;
mod hmac_utils;
mod signal;

// AES-GCM
#[pyfunction]
fn aes_gcm_encrypt<'a>(py: Python<'a>, plaintext: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let ct = aes_gcm::aes_gcm_encrypt(plaintext, key, iv, aad)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok(PyBytes::new_bound(py, &ct))
}

#[pyfunction]
fn aes_gcm_decrypt<'a>(py: Python<'a>, ciphertext: &[u8], key: &[u8], iv: &[u8], aad: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let pt = aes_gcm::aes_gcm_decrypt(ciphertext, key, iv, aad)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok(PyBytes::new_bound(py, &pt))
}

#[pyfunction]
fn aes_cbc_encrypt<'a>(py: Python<'a>, plaintext: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let ct = aes_gcm::aes_cbc_encrypt(plaintext, key, iv)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok(PyBytes::new_bound(py, &ct))
}

#[pyfunction]
fn aes_cbc_decrypt<'a>(py: Python<'a>, ciphertext: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let pt = aes_gcm::aes_cbc_decrypt(ciphertext, key, iv)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok(PyBytes::new_bound(py, &pt))
}

// Curve25519
#[pyfunction]
fn curve25519_generate_keypair<'a>(py: Python<'a>) -> PyResult<Bound<'a, PyDict>> {
    let keys = curve::generate_keypair();
    let dict = PyDict::new_bound(py);
    dict.set_item("private", PyBytes::new_bound(py, &keys["private"]))?;
    dict.set_item("public", PyBytes::new_bound(py, &keys["public"]))?;
    Ok(dict)
}

#[pyfunction]
fn curve25519_shared_key<'a>(py: Python<'a>, private_bytes: &[u8], public_bytes: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let shared = curve::shared_key(private_bytes, public_bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok(PyBytes::new_bound(py, &shared))
}

#[pyfunction]
fn curve25519_sign<'a>(py: Python<'a>, private_bytes: &[u8], message: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let sig = curve::sign(private_bytes, message)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok(PyBytes::new_bound(py, &sig))
}

#[pyfunction]
fn curve25519_verify(public_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> PyResult<bool> {
    curve::verify(public_bytes, message, signature_bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
}

// HKDF & HMAC
#[pyfunction]
fn hkdf_sha256<'a>(py: Python<'a>, input: &[u8], length: usize, salt: &[u8], info: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let out = hkdf_utils::hkdf_sha256(input, length, salt, info)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok(PyBytes::new_bound(py, &out))
}

#[pyfunction]
fn hmac_sha256<'a>(py: Python<'a>, key: &[u8], data: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let out = hmac_utils::hmac_sha256(key, data)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))?;
    Ok(PyBytes::new_bound(py, &out))
}

#[pyfunction]
fn sha256_hash<'a>(py: Python<'a>, data: &[u8]) -> PyResult<Bound<'a, PyBytes>> {
    let out = hmac_utils::sha256_hash(data);
    Ok(PyBytes::new_bound(py, &out))
}

#[pyfunction]
#[expect(clippy::too_many_arguments)]
#[pyo3(
    signature = (
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        remote_registration_id,
        remote_identity_key,
        signed_prekey_id,
        signed_prekey_public,
        signed_prekey_signature,
        session=None,
        prekey_id=None,
        prekey_public=None
    )
)]
fn signal_process_prekey_bundle<'a>(
    py: Python<'a>,
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    remote_registration_id: u32,
    remote_identity_key: &[u8],
    signed_prekey_id: u32,
    signed_prekey_public: &[u8],
    signed_prekey_signature: &[u8],
    session: Option<&[u8]>,
    prekey_id: Option<u32>,
    prekey_public: Option<&[u8]>,
) -> PyResult<Bound<'a, PyBytes>> {
    let out = signal::process_prekey_bundle_for_session(
        session,
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        remote_registration_id,
        remote_identity_key,
        signed_prekey_id,
        signed_prekey_public,
        signed_prekey_signature,
        prekey_id,
        prekey_public,
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)?;
    Ok(PyBytes::new_bound(py, &out))
}

#[pyfunction]
fn signal_session_encrypt<'a>(
    py: Python<'a>,
    session: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    plaintext: &[u8],
) -> PyResult<Bound<'a, PyDict>> {
    let out = signal::encrypt_with_session(
        session,
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        plaintext,
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)?;

    let dict = PyDict::new_bound(py);
    dict.set_item("type", out.msg_type)?;
    dict.set_item("ciphertext", PyBytes::new_bound(py, &out.ciphertext))?;
    dict.set_item("session", PyBytes::new_bound(py, &out.session))?;
    Ok(dict)
}

#[pyfunction]
fn signal_session_decrypt_prekey<'a>(
    py: Python<'a>,
    session: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    ciphertext: &[u8],
) -> PyResult<Bound<'a, PyDict>> {
    let out = signal::decrypt_with_session_prekey(
        session,
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        ciphertext,
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)?;

    let dict = PyDict::new_bound(py);
    dict.set_item("type", out.msg_type)?;
    dict.set_item("ciphertext", PyBytes::new_bound(py, &out.ciphertext))?;
    dict.set_item("session", PyBytes::new_bound(py, &out.session))?;
    Ok(dict)
}

#[pyfunction]
fn signal_session_decrypt_whisper<'a>(
    py: Python<'a>,
    session: &[u8],
    identity_private: &[u8],
    registration_id: u32,
    remote_name: &str,
    remote_device: u32,
    ciphertext: &[u8],
) -> PyResult<Bound<'a, PyDict>> {
    let out = signal::decrypt_with_session_whisper(
        session,
        identity_private,
        registration_id,
        remote_name,
        remote_device,
        ciphertext,
    )
    .map_err(pyo3::exceptions::PyValueError::new_err)?;

    let dict = PyDict::new_bound(py);
    dict.set_item("type", out.msg_type)?;
    dict.set_item("ciphertext", PyBytes::new_bound(py, &out.ciphertext))?;
    dict.set_item("session", PyBytes::new_bound(py, &out.session))?;
    Ok(dict)
}

#[pymodule]
fn _crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    m.add_function(wrap_pyfunction!(aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_cbc_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(curve25519_generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(curve25519_shared_key, m)?)?;
    m.add_function(wrap_pyfunction!(curve25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(curve25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(hkdf_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_hash, m)?)?;
    m.add_function(wrap_pyfunction!(signal_process_prekey_bundle, m)?)?;
    m.add_function(wrap_pyfunction!(signal_session_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(signal_session_decrypt_prekey, m)?)?;
    m.add_function(wrap_pyfunction!(signal_session_decrypt_whisper, m)?)?;
    Ok(())
}
