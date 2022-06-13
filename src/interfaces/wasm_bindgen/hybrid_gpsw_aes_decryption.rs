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

use cosmian_crypto_base::symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto};
use lazy_static::lazy_static;
use wasm_bindgen::prelude::*;

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{scheme::GpswDecryptionKey, AbeScheme, AsBytes, Gpsw},
    },
    interfaces::hybrid_crypto::{decrypt_hybrid_block, decrypt_hybrid_header, ClearTextHeader},
};

pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

/// Extract header from encrypted bytes
#[wasm_bindgen]
pub fn webassembly_get_encrypted_header_size(
    encrypted_bytes: js_sys::Uint8Array,
) -> Result<u32, JsValue> {
    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_bytes.length() < 4 {
        return Err(JsValue::from_str(
            "Encrypted value must be at least 4-bytes long",
        ));
    }

    //
    // Recover header from `encrypted_bytes`
    let mut header_size_bytes = [0; 4];
    header_size_bytes.copy_from_slice(&encrypted_bytes.to_vec()[0..4]);
    let header_size = u32::from_be_bytes(header_size_bytes);

    Ok(header_size)
}

// -------------------------------
//         Decryption
// -------------------------------

/// Decrypt with a user decryption key an encrypted header
/// of a resource encrypted using an hybrid crypto scheme.
#[wasm_bindgen]
pub fn webassembly_decrypt_hybrid_header(
    user_decryption_key_bytes: js_sys::Uint8Array,
    encrypted_header_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    //
    // Check `user_decryption_key_bytes` input param and store it locally
    if user_decryption_key_bytes.length() == 0 {
        return Err(JsValue::from_str("User decryption key is empty"));
    }

    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_header_bytes.length() < 4 {
        return Err(JsValue::from_str("Encrypted value is empty"));
    }

    //
    // Parse user decryption key
    let user_decryption_key =
        UserDecryptionKey::from_bytes(user_decryption_key_bytes.to_vec().as_slice()).map_err(
            |e| return JsValue::from_str(&format!("Error deserializing user decryption key: {e}")),
        )?;

    //
    // Finally decrypt symmetric key using given user decryption key
    let cleartext_header: ClearTextHeader<Aes256GcmCrypto> =
        decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
            &user_decryption_key,
            encrypted_header_bytes.to_vec().as_slice(),
        )
        .map_err(|e| return JsValue::from_str(&format!("Error decrypting hybrid header: {e}")))?;

    let cleartext_header_bytes = cleartext_header.as_bytes().map_err(|e| {
        return JsValue::from_str(&format!("Error serializing cleartext header: {e}"));
    })?;

    Ok(js_sys::Uint8Array::from(&cleartext_header_bytes[..]))
}

// A cache of the decryption caches
lazy_static! {
    static ref DECRYPTION_CACHE_MAP: RwLock<HashMap<i32, DecryptionCache>> =
        RwLock::new(HashMap::new());
    static ref NEXT_DECRYPTION_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

/// A Decryption Cache that will be used to cache Rust side
/// the User Decryption Key when performing serial decryptions
pub struct DecryptionCache {
    user_decryption_key: GpswDecryptionKey<Bls12_381>,
}

#[wasm_bindgen]
/// Prepare decryption cache (avoiding user decryption key deserialization)
pub fn webassembly_create_decryption_cache(
    user_decryption_key: js_sys::Uint8Array,
) -> Result<i32, JsValue> {
    //
    // Check `user_decryption_key_bytes` input param and store it locally
    if user_decryption_key.length() == 0 {
        return Err(JsValue::from_str("User decryption key is empty"));
    }
    //
    // Parse user decryption key
    let user_decryption_key =
        UserDecryptionKey::from_bytes(user_decryption_key.to_vec().as_slice()).map_err(|e| {
            return JsValue::from_str(&format!("Error deserializing user decryption key: {e}"));
        })?;

    let cache = DecryptionCache {
        user_decryption_key,
    };
    let id = NEXT_DECRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.insert(id, cache);
    Ok(id)
}

#[wasm_bindgen]
pub fn webassembly_destroy_decryption_cache(cache_handle: i32) -> Result<(), JsValue> {
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.remove(&cache_handle);
    Ok(())
}

#[wasm_bindgen]
/// Decrypt ABE header
pub fn webassembly_decrypt_hybrid_header_using_cache(
    cache_handle: i32,
    encrypted_header: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let map = DECRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the decryption cache failed");
    let cache = map
        .get(&cache_handle)
        .expect("Hybrid Cipher: no decryption cache with handle");

    //
    // Finally decrypt symmetric key using given user decryption key
    let cleartext_header: ClearTextHeader<Aes256GcmCrypto> =
        decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
            &cache.user_decryption_key,
            encrypted_header.to_vec().as_slice(),
        )
        .map_err(|e| return JsValue::from_str(&format!("Error decrypting hybrid header: {e}")))?;

    let cleartext_header_bytes = cleartext_header.as_bytes().map_err(|e| {
        return JsValue::from_str(&format!("Error serializing cleartext header: {e}"));
    })?;

    Ok(js_sys::Uint8Array::from(&cleartext_header_bytes[..]))
}

/// Symmetrically Decrypt encrypted data in a block.
#[wasm_bindgen]
pub fn webassembly_decrypt_hybrid_block(
    symmetric_key_bytes: js_sys::Uint8Array,
    uid_bytes: Option<js_sys::Uint8Array>,
    block_number: Option<usize>,
    encrypted_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    //
    // Check `symmetric_key_bytes` input param and store it locally
    if symmetric_key_bytes.length() != 32 {
        return Err(JsValue::from_str("Symmetric key must be 32-bytes long"));
    }

    //
    // Check `encrypted_bytes` input param and store it locally
    if encrypted_bytes.length() == 0 {
        return Err(JsValue::from_str("Encrypted value is empty"));
    }

    //
    // Parse symmetric key
    let symmetric_key = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(
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
    let cleartext = decrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &symmetric_key,
        &uid,
        block_number_value as usize,
        &encrypted_bytes.to_vec(),
    )
    .map_err(|e| {
        return JsValue::from_str(&format!(
            "Error decrypting block:
    {e}"
        ));
    })?;

    Ok(js_sys::Uint8Array::from(&cleartext[..]))
}
