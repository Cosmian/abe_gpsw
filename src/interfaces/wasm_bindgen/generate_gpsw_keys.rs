// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{scheme::GpswMasterPrivateKey, AsBytes, Gpsw},
        Engine,
    },
    interfaces::policy::{AccessPolicy, Policy},
};

/// Generate the master authority keys for supplied Policy
///
///  - `policy` : Policy to use to generate the keys (serialized from JSON)
#[wasm_bindgen]
pub fn webassembly_generate_master_keys(
    policy_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let policy: Policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy:{e}")))?;

    // Create ABE GPSW keys
    let (private_key, public_key, _delegation_key) = Engine::<Gpsw<Bls12_381>>::new()
        .generate_master_key(&policy)
        .map_err(|e| JsValue::from_str(&format!("Error generating master keys: {e}")))?;

    // Serialize master keys
    let private_keys_bytes = private_key
        .as_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing master private key: {e}")))?;
    let public_keys_bytes = public_key
        .as_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing master public key: {e}")))?;

    let mut master_keys_bytes =
        Vec::<u8>::with_capacity(4 + private_keys_bytes.len() + public_keys_bytes.len());
    master_keys_bytes.extend_from_slice(&u32::to_be_bytes(private_keys_bytes.len() as u32));
    master_keys_bytes.extend_from_slice(&private_keys_bytes);
    master_keys_bytes.extend_from_slice(&public_keys_bytes);
    Ok(js_sys::Uint8Array::from(&master_keys_bytes[..]))
}

/// Generate a user private key.
///
/// - `master_private_key_bytes`    : master private key in bytes
/// - `access_policy`               : user access policy (boolean expression as
///   string)
/// - `policy_bytes`                : global policy (serialized from JSON)
#[wasm_bindgen]
pub fn webassembly_generate_user_private_key(
    master_private_key_bytes: js_sys::Uint8Array,
    access_policy_str: &str,
    policy_bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let private_key =
        GpswMasterPrivateKey::<Bls12_381>::from_bytes(master_private_key_bytes.to_vec().as_slice())
            .map_err(|e| JsValue::from_str(&format!("Error deserializing private key: {e}")))?;
    let policy = serde_json::from_slice(policy_bytes.to_vec().as_slice())
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy: {e}")))?;
    let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
        .map_err(|e| JsValue::from_str(&format!("Error deserializing access policy: {e}")))?;

    // Generate user decryption key
    let user_key = Engine::<Gpsw<Bls12_381>>::new()
        .generate_user_key(&policy, &private_key, &access_policy)
        .map_err(|e| JsValue::from_str(&format!("Error generating user private key: {e}")))?;

    let user_key_bytes = user_key
        .as_bytes()
        .map_err(|e| JsValue::from_str(&format!("Error serializing user key: {e}")))?;
    Ok(js_sys::Uint8Array::from(user_key_bytes.as_slice()))
}
