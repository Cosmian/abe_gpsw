#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use std::{
    collections::HashMap,
    convert::From,
    sync::{
        atomic::{AtomicI32, Ordering},
        RwLock,
    },
};

use cosmian_crypto_base::symmetric_crypto::{
    aes_256_gcm_pure::Aes256GcmCrypto, Key, SymmetricCrypto,
};
use lazy_static::lazy_static;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{scheme::GpswDecryptionKey, AbeScheme, AsBytes, Gpsw},
    },
    interfaces::hybrid_crypto::{decrypt_hybrid_block, decrypt_hybrid_header, ClearTextHeader},
};

pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    fn alert(s: &str);
}

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
    // Check `user_decryption_key_bytes` input param and store it locally
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
pub fn test_non_reg_decrypt_hybrid_header() {
    let user_decryption_key_hex = "0000000280bcdf7a99a04c2da5651ae4a3e33bab086f40443ffb7168a97c3df52a5d868e34456f5e11d165e3131a56f25442e8e608d978a73eed818074aeba1ee8babf11dd16e35224f603bcb390bc84ec6c3dd1eba8d4c8fdbcbcb3fad08416885e5d44ab11254bcfb28cc8d6cd124cb1c51fffae9dd07bc158260e681e04587618b94dd2fe1da65ffb3087a04a8c9951e2333703a0b9c54dd23f97a5da42ee447a4aafa89ee29341fe6c743f8ccce5b965e18e2498e82de3d80c7f9953c0dfb79ce5600000000200000002000000010000000401000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73";
    let user_decryption_key_bytes = hex::decode(&user_decryption_key_hex).unwrap();
    let user_decryption_key = UserDecryptionKey::from_bytes(&user_decryption_key_bytes)
        .expect("Hybrid Cipher: invalid user decryption key");

    let encrypted_header_hex = "00000190000000020000000100000004000000028a4741b3038d750636c82db4def6b9e1f9a7dc3e617a9183e5ea8b5542ac90be2173a9107d394a0e387ce62f52514b4db9788f2ab5e0d81960612097934d8023e3f9801a216258bf865c3de17447c9351b159e5cd412726bb0e708dd6cd7c9a297a54761db9ef6052a166907b2ba70eb33c1229b4e8cb584d0cd6c955443089d84f4c37afb24016c07d349884abfdf6c15b14b200a0bd1503690f72090ab5a09f7a75e8374d2edfd44f88d3638370d36a075f1bec2b439db0879b6a66a438123015f868a63e03a9973ea966f7736e825114359fd8d386ee632554ad2aa87dca80375e436cf0db232e251333fdf7ffb010bae96094d968b1573cf9f40c14351ecd5fd3eb29391288a33f355629723ec70935b0c736e1fa39d2d96d7dcefbd4be8193f5a2f23420fe23cf434f6797c793af3e9213a19b94823226e7a7276bb5df4c18090d346f1916dc69680e5c3c07ca80bee2c08aadd97e98b5ed1eab7952bc39b1edfc53a417db652caef629e0e29f78704da8fab27d98e3c8edf0de17864f24fa16e187aedad3f4c2ab98e0000001421cc8a57e3d335f4be5dfbe5efa2c83a3ff6c9e5";
    let encrypted_header_bytes = hex::decode(encrypted_header_hex).unwrap();

    let _clear_text = decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &user_decryption_key,
        &encrypted_header_bytes,
    )
    .unwrap();
}

#[wasm_bindgen_test]
pub fn test_non_reg_decrypt_hybrid_block() {
    let symmetric_key_hex = "802de96f19589fbc0eb2f26705dc1ed261e9c80f2fec301ca7d0ecea3176405b";
    let symmetric_key =
        <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(hex::decode(symmetric_key_hex).unwrap())
            .unwrap();
    let uid_hex = "cd8ca2eeb654b5f39f347f4e3f91b3a15c450c1e52c40716237b4c18510f65b4";
    let encrypted_bytes = "e09ba17fdff90afbb18546211268b8aef6517a73b701283ab334c0720372f565c751a311c1ec09a6bbb070f8a1961ca3f048b280ea36a578a0068edea8408f3cf4ab26f5a71933dffed384ea7d33e42c16fe17a1026937a345386bb980917d6d2175a48b6d69e8322689dde0bf99cee9d2da5bbee1f29b2005725b6969021462e6608284a5135677b03d8fcce03563cc4d8988f455d27b95ef62080f4c2f18e7897636ac69e9d216668765d2025f66c805d549c4ef779c32ac3286bee8d35c1b758b51f1686d2aea996cc1f3bfff2aea7d605cce963e5bc69f77f284a1c05b803df08fcdec6a6d4f0c74ad8f6076d9ca692642dcdff64a34d1fbbb4d57aea776ce8032b03d63c9e376377fb95725b6d3ac6be3a29f47d15eb22b5c81bf6168785844da8d22914076415957d9e253142f14c5c68fbe1108d74832e2347425f89b46321ac0c7b939f793e3c39e5dbb83d9e6be29db4aa3df0e645cc859aac9a0324d546b70856e2ae89c77b87a8e25eac90f9265642bbd8c407f0aa307aef613bd79fa8fd6c959c959007791621e5fe047edfcadae2c195bb681b6621a9583c8d51911e39df50331b495b603fbf826eebeffe26cd2bc0287a280801bc54cfa9fed1279a58843bb8ea1262982753481dc61852cca49279d0de5e287f6a43dca38";

    let _clear_text =
        decrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
            &symmetric_key,
            &hex::decode(uid_hex).unwrap(),
            0,
            &hex::decode(encrypted_bytes).unwrap(),
        )
        .unwrap();
}
