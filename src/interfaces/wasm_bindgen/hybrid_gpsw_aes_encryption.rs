#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use std::{
    collections::HashMap,
    convert::{From, TryFrom},
    sync::{
        atomic::{AtomicI32, Ordering},
        RwLock,
    },
};

use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Key, SymmetricCrypto},
};
use lazy_static::lazy_static;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

use super::bytes_to_js_array;
use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, AsBytes, Gpsw},
    },
    interfaces::{
        hybrid_crypto::{
            decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_block,
            encrypt_hybrid_header, EncryptedHeader,
        },
        policy::{Attributes, Policy},
    },
};

pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;
type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;

// -------------------------------
//         Encryption
// -------------------------------

/// Encrypt with the public key a symmetric key
#[wasm_bindgen]
pub fn webassembly_encrypt_hybrid_header(
    policy_bytes: js_sys::Uint8Array,
    public_key_bytes: js_sys::Uint8Array,
    attributes_str: &str,
    uid_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    //
    // Check input arguments emptiness
    if policy_bytes.length() == 0 {
        return Err(JsValue::from_str("Policy as bytes is empty"));
    }
    if public_key_bytes.length() == 0 {
        return Err(JsValue::from_str("Public Key as bytes is empty"));
    }
    if uid_bytes.length() == 0 {
        return Err(JsValue::from_str("UID as bytes is empty"));
    }
    if attributes_str.is_empty() {
        return Err(JsValue::from_str("Attributes are empty"));
    }

    // Convert JS type
    let policy: Policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing Policy: {e:?}")))?;
    let public_key = PublicKey::from_bytes(public_key_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing Public Key: {e:?}")))?;

    let encrypted_header = encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        Attributes::try_from(attributes_str)
            .map_err(|e| JsValue::from_str(&format!("Error parsing attributes: {e:?}")))?
            .attributes(),
        Metadata {
            uid: uid_bytes.to_vec(),
            additional_data: None,
        },
    )
    .map_err(|e| JsValue::from_str(&format!("Error encrypting header: {e:?}")))?;

    //
    // Flatten struct Encrypted Header
    let encrypted_header_bytes = encrypted_header
        .as_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing encrypted header: {e:?}")))?;
    Ok(js_sys::Uint8Array::from(&encrypted_header_bytes[..]))
}

// A cache of the decryption caches
lazy_static! {
    static ref ENCRYPTION_CACHE_MAP: RwLock<HashMap<i32, EncryptionCache>> =
        RwLock::new(HashMap::new());
    static ref NEXT_ENCRYPTION_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

/// An Encryption Cache that will be used to cache Rust side
/// the Public Key when performing serial encryptions
pub struct EncryptionCache {
    policy: Policy,
    public_key: PublicKey,
}

#[wasm_bindgen]
/// Prepare encryption cache (avoiding public key deserialization)
pub fn webassembly_create_encryption_cache(
    policy_bytes: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
) -> Result<i32, JsValue> {
    //
    // Check policy emptiness
    if policy_bytes.length() == 0 {
        return Err(JsValue::from_str("Policy as bytes is empty"));
    }
    //
    // Check `public_key` input param and store it locally
    if public_key.length() == 0 {
        return Err(JsValue::from_str("Public key is empty"));
    }

    //
    // Convert JS type
    let policy: Policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing Policy: {e:?}")))?;

    //
    // Parse public key
    let public_key = PublicKey::from_bytes(public_key.to_vec().as_slice()).map_err(|e| {
        return JsValue::from_str(&format!("Error deserializing public key: {e}"));
    })?;

    let cache = EncryptionCache { policy, public_key };
    let id = NEXT_ENCRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.insert(id, cache);
    Ok(id)
}

#[wasm_bindgen]
pub fn webassembly_destroy_encryption_cache(cache_handle: i32) -> Result<(), JsValue> {
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.remove(&cache_handle);
    Ok(())
}

#[wasm_bindgen]
/// Encrypt symmetric key
pub fn webassembly_encrypt_hybrid_header_using_cache(
    cache_handle: i32,
    attributes_str: &str,
    uid_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let map = ENCRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the encryption cache failed");
    let cache = map
        .get(&cache_handle)
        .expect("Hybrid Cipher: no encryption cache with handle");

    //
    // Finally encrypt symmetric key using given public key
    let encrypted_header = encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &cache.policy,
        &cache.public_key,
        Attributes::try_from(attributes_str)
            .map_err(|e| JsValue::from_str(&format!("Error parsing attributes: {e:?}")))?
            .attributes(),
        Metadata {
            uid: uid_bytes.to_vec(),
            additional_data: None,
        },
    )
    .map_err(|e| JsValue::from_str(&format!("Error encrypting header: {e:?}")))?;

    //
    // Flatten struct Encrypted Header
    let encrypted_header_bytes = encrypted_header
        .as_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing encrypted header: {e:?}")))?;
    Ok(js_sys::Uint8Array::from(&encrypted_header_bytes[..]))
}

/// Symmetrically Decrypt encrypted data in a block.
#[wasm_bindgen]
pub fn webassembly_encrypt_hybrid_block(
    symmetric_key_bytes: js_sys::Uint8Array,
    uid_bytes: Option<js_sys::Uint8Array>,
    block_number: Option<usize>,
    data_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    //
    // Check `user_decryption_key_bytes` input param and store it locally
    if symmetric_key_bytes.length() != 32 {
        return Err(JsValue::from_str("Symmetric key must be 32-bytes long"));
    }

    //
    // Check `encrypted_bytes` input param and store it locally
    if data_bytes.length() == 0 {
        return Err(JsValue::from_str("Plaintext value is empty"));
    }

    //
    // Parse symmetric key
    let symmetric_key = <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(
        symmetric_key_bytes.to_vec(),
    )
    .map_err(|e| {
        return JsValue::from_str(&format!(
            "Error parsing
    symmetric key: {e}"
        ));
    })?;

    let uid = uid_bytes.map_or(vec![], |v| v.to_vec());
    let block_number_value = block_number.unwrap_or(0);
    //
    // Decrypt block
    let ciphertext = encrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &symmetric_key,
        &uid,
        block_number_value as usize,
        &data_bytes.to_vec(),
    )
    .map_err(|e| {
        return JsValue::from_str(&format!(
            "Error encrypting block:
    {e}"
        ));
    })?;

    Ok(js_sys::Uint8Array::from(&ciphertext[..]))
}

#[wasm_bindgen_test]
pub fn test_encrypt_hybrid_header() {
    let public_key_json: Value = serde_json::from_str(include_str!(
        "../hybrid_crypto/tests/public_master_key.json"
    ))
    .unwrap();
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let public_key_bytes = hex::decode(hex_key).unwrap();

    // Policy
    let policy_hex = &key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .unwrap();
    let policy_bytes = hex::decode(policy_hex).unwrap();

    // Prepare JS inputs
    let policy_js = bytes_to_js_array(&policy_bytes);
    let public_key_js = bytes_to_js_array(&public_key_bytes);
    let uid_js = js_sys::Uint8Array::new(&JsValue::from_str("12345678"));

    let encrypted_header_js = webassembly_encrypt_hybrid_header(
        policy_js,
        public_key_js,
        "Department::FIN, Security Level::Confidential",
        uid_js,
    )
    .unwrap();

    let encrypted_header =
        EncryptedHeader::<Aes256GcmCrypto>::from_bytes(&encrypted_header_js.to_vec()[..]).unwrap();

    // Decrypt
    let user_decryption_key_json: Value = serde_json::from_str(include_str!(
        "../hybrid_crypto/tests/fin_confidential_user_key.json"
    ))
    .unwrap();
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let user_decryption_key =
        UserDecryptionKey::from_bytes(&hex::decode(hex_key).unwrap()).unwrap();
    decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &user_decryption_key,
        &encrypted_header.encrypted_header_bytes,
    )
    .unwrap();
}

#[wasm_bindgen_test]
pub fn test_encrypt_hybrid_block() {
    let symmetric_key_bytes =
        hex::decode("802de96f19589fbc0eb2f26705dc1ed261e9c80f2fec301ca7d0ecea3176405b").unwrap();
    let uid_bytes =
        hex::decode("cd8ca2eeb654b5f39f347f4e3f91b3a15c450c1e52c40716237b4c18510f65b4").unwrap();

    let symmetric_key =
        <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(symmetric_key_bytes.clone()).unwrap();

    let symmetric_key_js = bytes_to_js_array(&symmetric_key_bytes);
    let uid_js = bytes_to_js_array(&uid_bytes);
    let data_js = bytes_to_js_array(&[1, 2, 3, 4, 5, 6, 7, 8]);

    let ciphertext =
        webassembly_encrypt_hybrid_block(symmetric_key_js, Some(uid_js), Some(0), data_js).unwrap();

    let mut ciphertext_bytes = vec![0_u8; ciphertext.length() as usize];
    ciphertext.copy_to(&mut ciphertext_bytes[..]);

    let _clear_text =
        decrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
            &symmetric_key,
            &uid_bytes,
            0,
            &ciphertext_bytes,
        )
        .unwrap();
}
