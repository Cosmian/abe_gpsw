#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use std::convert::From;

use cosmian_crypto_base::symmetric_crypto::{
    aes_256_gcm_pure::Aes256GcmCrypto, Key, SymmetricCrypto,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, AsBytes, Gpsw},
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
