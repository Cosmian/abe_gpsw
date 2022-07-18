// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use std::convert::TryInto;

use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    KeyTrait,
};
use pyo3::{exceptions::PyTypeError, pyfunction, PyResult};

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, AsBytes, Gpsw},
    },
    interfaces::hybrid_crypto::{
        decrypt_hybrid_block as core_decrypt_hybrid_block,
        decrypt_hybrid_header as core_decrypt_hybrid_header,
        encrypt_hybrid_block as core_encrypt_hybrid_block,
        encrypt_hybrid_header as core_encrypt_hybrid_header,
    },
};
use abe_policy::Attribute;

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

pub const MAX_CLEAR_TEXT_SIZE: usize = 1 << 30;

/// Get size of header inside an encrypted data
/// * ENCRYPTED_DATA = HEADER_SIZE (4 bytes) | HEADER | AES_DATA
///
/// # Arguments
///
/// * `encrypted_bytes`: encrypted data
///
/// # Returns
///
/// * the length header
///
/// # Errors
///
/// Function fails if input data is less than 4 bytes
#[pyfunction]
pub fn get_encrypted_header_size(encrypted_bytes: Vec<u8>) -> PyResult<u32> {
    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_bytes.len() < 4 {
        return Err(PyTypeError::new_err(
            "Encrypted value must be at least 4-bytes long",
        ));
    }

    //
    // Recover header size from `encrypted_bytes`
    Ok(u32::from_be_bytes(encrypted_bytes[..4].try_into()?))
}

/// Generate an encrypted header. A header contains the following elements:
///
/// - `encapsulation_size`  : the size of the symmetric key encapsulation (u32)
/// - `encapsulation`       : symmetric key encapsulation using GPSW
/// - `encrypted_metadata`  : Optional metadata encrypted using the DEM
///
/// Parameters:
///
/// - `metadata_bytes`         : meta data
/// - `policy_bytes`           : global policy
/// - `attributes_bytes`       : access policy
/// - `public_key_bytes`       : GPSW public key
#[pyfunction]
pub fn encrypt_hybrid_header(
    metadata_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    attributes_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    //
    // Deserialize inputs
    let metadata: Metadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing metadata: {e}")))?;
    let policy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing policy: {e}")))?;
    let attributes: Vec<Attribute> = serde_json::from_slice(&attributes_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))?;
    let public_key = PublicKey::try_from_bytes(&public_key_bytes)?;

    //
    // Encrypt
    let encrypted_header = core_encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &attributes,
        Some(metadata),
    )
    .map_err(|e| PyTypeError::new_err(format!("Error encrypting header: {e}")))?;

    Ok((
        encrypted_header.symmetric_key.to_bytes(),
        encrypted_header.encrypted_header_bytes,
    ))
}

/// [Private internal function] Decrypt the given header bytes using a user
/// decryption key.
///
/// - `user_decryption_key_bytes`     : private key to use for decryption
/// - `encrypted_header_bytes`        : encrypted header bytes
fn internal_decrypt_hybrid_header(
    user_decryption_key_bytes: &[u8],
    encrypted_header_bytes: &[u8],
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    //
    // Parse user decryption key
    let user_decryption_key = UserDecryptionKey::try_from_bytes(user_decryption_key_bytes)?;

    //
    // Finally decrypt symmetric key using given user decryption key
    let cleartext_header = core_decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &user_decryption_key,
        encrypted_header_bytes,
    )
    .map_err(|e| PyTypeError::new_err(format!("Error decrypting header: {e}")))?;

    let metadata = cleartext_header
        .meta_data
        .to_bytes()
        .map_err(|e| PyTypeError::new_err(format!("Serialize metadata failed: {e}")))?;

    Ok((cleartext_header.symmetric_key.to_bytes(), metadata))
}

/// Decrypt the given header bytes using a user decryption key.
///
/// - `user_decryption_key_bytes`     : private key to use for decryption
/// - `encrypted_header_bytes`        : encrypted header bytes
#[pyfunction]
pub fn decrypt_hybrid_header(
    user_decryption_key_bytes: Vec<u8>,
    encrypted_header_bytes: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    internal_decrypt_hybrid_header(&user_decryption_key_bytes, &encrypted_header_bytes)
}

/// Encrypt data symmetrically in a block.
///
/// The `uid` should be different for every resource  and `block_number`
/// different for every block. They are part of the AEAD of the symmetric scheme
/// if any.
#[pyfunction]
pub fn encrypt_hybrid_block(
    symmetric_key_bytes: Vec<u8>,
    uid_bytes: Vec<u8>,
    block_number: usize,
    plaintext_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    //
    // Parse symmetric key
    let symmetric_key =
        <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(&symmetric_key_bytes)
            .map_err(|e| PyTypeError::new_err(format!("Deserialize symmetric key failed: {e}")))?;

    //
    // Encrypt block
    core_encrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &symmetric_key,
        &uid_bytes,
        block_number,
        &plaintext_bytes,
    )
    .map_err(|e| PyTypeError::new_err(format!("Error encrypting block: {e}")))
}

fn internal_decrypt_hybrid_block(
    symmetric_key_bytes: &[u8],
    uid_bytes: &[u8],
    block_number: usize,
    encrypted_bytes: &[u8],
) -> PyResult<Vec<u8>> {
    //
    // Parse symmetric key
    let symmetric_key =
        <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from_bytes(symmetric_key_bytes)
            .map_err(|e| PyTypeError::new_err(format!("Deserialize symmetric key failed: {e}")))?;

    //
    // Decrypt block
    core_decrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &symmetric_key,
        uid_bytes,
        block_number,
        encrypted_bytes,
    )
    .map_err(|e| PyTypeError::new_err(format!("Error encrypting block: {e}")))
}

/// Symmetrically Decrypt encrypted data in a block.
///
/// The `uid` and `block_number` are part of the AEAD
/// of the crypto scheme (when applicable)
#[pyfunction]
pub fn decrypt_hybrid_block(
    symmetric_key_bytes: Vec<u8>,
    uid_bytes: Vec<u8>,
    block_number: usize,
    encrypted_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    internal_decrypt_hybrid_block(
        &symmetric_key_bytes,
        &uid_bytes,
        block_number,
        &encrypted_bytes,
    )
}

/// Hybrid encryption producing:
/// - ENCRYPTED_DATA = HEADER_SIZE | HEADER | AES_DATA
#[pyfunction]
pub fn encrypt(
    metadata_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    attributes_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    plaintext: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let metadata: Metadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing metadata: {e}")))?;

    let header = encrypt_hybrid_header(
        metadata_bytes,
        policy_bytes,
        attributes_bytes,
        public_key_bytes,
    )?;

    let ciphertext = encrypt_hybrid_block(header.0, metadata.uid, 0, plaintext)?;

    // Encrypted value is composed of: HEADER_LEN (4 bytes) | HEADER | AES_DATA
    let mut encrypted = Vec::<u8>::with_capacity(4 + header.1.len() + ciphertext.len());
    encrypted.extend_from_slice(&u32::to_be_bytes(header.1.len() as u32));
    encrypted.extend_from_slice(&header.1);
    encrypted.extend_from_slice(&ciphertext);
    Ok(encrypted)
}

/// Hybrid decryption
#[pyfunction]
pub fn decrypt(user_decryption_key_bytes: Vec<u8>, encrypted_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
    let header_size = get_encrypted_header_size(encrypted_bytes.clone())?;
    let header = &encrypted_bytes[4..4 + header_size as usize];
    let ciphertext = &encrypted_bytes[4 + header_size as usize..];

    let cleartext_header = internal_decrypt_hybrid_header(&user_decryption_key_bytes, header)?;

    let metadata = Metadata::from_bytes(&cleartext_header.1)
        .map_err(|e| PyTypeError::new_err(format!("Error deserializing metadata: {e}")))?;

    internal_decrypt_hybrid_block(&cleartext_header.0, &metadata.uid, 0, ciphertext)
}
