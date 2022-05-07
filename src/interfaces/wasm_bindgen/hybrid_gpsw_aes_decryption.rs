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
        gpsw::{scheme::GpswDecryptionKey, AbeScheme, AsBytes, Gpsw},
    },
    interfaces::{
        hybrid_crypto::{
            decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_header, ClearTextHeader,
        },
        policy::{Attributes, Policy},
    },
};

pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
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

    Ok(js_sys::Uint8Array::from(
        &cleartext_header.symmetric_key.as_bytes()[..],
    ))
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

    Ok(js_sys::Uint8Array::from(
        &cleartext_header.symmetric_key.as_bytes()[..],
    ))
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

#[wasm_bindgen_test]
pub fn test_decrypt_hybrid_header() {
    let public_key_json: Value = serde_json::from_str(include_str!(
        "../hybrid_crypto/tests/public_master_key.json"
    ))
    .unwrap();
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let public_key = PublicKey::from_bytes(&hex::decode(hex_key).unwrap()).unwrap();

    // Policy
    let policy_hex = &key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .unwrap();
    let policy: Policy = serde_json::from_slice(&hex::decode(policy_hex).unwrap()).unwrap();

    let policy_attributes =
        Attributes::try_from("Department::FIN, Security Level::Confidential").unwrap();

    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };
    let encrypted_header = encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        policy_attributes.attributes(),
        meta_data,
    )
    .unwrap();

    //
    // Check webassembly function
    let user_decryption_key_json: Value = serde_json::from_str(include_str!(
        "../hybrid_crypto/tests/fin_confidential_user_key.json"
    ))
    .unwrap();
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let user_decryption_key_bytes = hex::decode(hex_key).unwrap();
    // Prepare JS inputs
    let user_decryption_key_js = bytes_to_js_array(&user_decryption_key_bytes);
    let encrypted_header_js = bytes_to_js_array(&encrypted_header.encrypted_header_bytes);

    webassembly_decrypt_hybrid_header(user_decryption_key_js, encrypted_header_js).unwrap();
}

#[wasm_bindgen_test]
pub fn test_non_reg_decrypt_hybrid_block() {
    let symmetric_key_bytes =
        hex::decode("802de96f19589fbc0eb2f26705dc1ed261e9c80f2fec301ca7d0ecea3176405b").unwrap();
    let uid_bytes =
        hex::decode("cd8ca2eeb654b5f39f347f4e3f91b3a15c450c1e52c40716237b4c18510f65b4").unwrap();
    let encrypted_bytes = hex::decode("e09ba17fdff90afbb18546211268b8aef6517a73b701283ab334c0720372f565c751a311c1ec09a6bbb070f8a1961ca3f048b280ea36a578a0068edea8408f3cf4ab26f5a71933dffed384ea7d33e42c16fe17a1026937a345386bb980917d6d2175a48b6d69e8322689dde0bf99cee9d2da5bbee1f29b2005725b6969021462e6608284a5135677b03d8fcce03563cc4d8988f455d27b95ef62080f4c2f18e7897636ac69e9d216668765d2025f66c805d549c4ef779c32ac3286bee8d35c1b758b51f1686d2aea996cc1f3bfff2aea7d605cce963e5bc69f77f284a1c05b803df08fcdec6a6d4f0c74ad8f6076d9ca692642dcdff64a34d1fbbb4d57aea776ce8032b03d63c9e376377fb95725b6d3ac6be3a29f47d15eb22b5c81bf6168785844da8d22914076415957d9e253142f14c5c68fbe1108d74832e2347425f89b46321ac0c7b939f793e3c39e5dbb83d9e6be29db4aa3df0e645cc859aac9a0324d546b70856e2ae89c77b87a8e25eac90f9265642bbd8c407f0aa307aef613bd79fa8fd6c959c959007791621e5fe047edfcadae2c195bb681b6621a9583c8d51911e39df50331b495b603fbf826eebeffe26cd2bc0287a280801bc54cfa9fed1279a58843bb8ea1262982753481dc61852cca49279d0de5e287f6a43dca38").unwrap();

    let symmetric_key_js = bytes_to_js_array(&symmetric_key_bytes);
    let uid_js = bytes_to_js_array(&uid_bytes);
    let encrypted_js = bytes_to_js_array(&encrypted_bytes);

    webassembly_decrypt_hybrid_block(symmetric_key_js, Some(uid_js), Some(0), encrypted_js)
        .unwrap();
}
