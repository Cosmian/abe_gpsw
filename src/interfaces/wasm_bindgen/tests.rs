// needed to remove wasm_bindgen warnings
#![allow(non_upper_case_globals)]
#![allow(clippy::unused_unit)]
// Wait for `wasm-bindgen` issue 2774: https://github.com/rustwasm/wasm-bindgen/issues/2774

use std::convert::{TryFrom, TryInto};

use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
};
use js_sys::Uint8Array;
use serde_json::Value;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

use super::{
    generate_gpsw_keys::{webassembly_generate_master_keys, webassembly_generate_user_private_key},
    hybrid_gpsw_aes_decryption::{
        webassembly_decrypt_hybrid_block, webassembly_decrypt_hybrid_header,
    },
    hybrid_gpsw_aes_encryption::{
        webassembly_encrypt_hybrid_block, webassembly_encrypt_hybrid_header, MAX_CLEAR_TEXT_SIZE,
    },
};
use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{
            scheme::{GpswMasterPrivateKey, GpswMasterPublicKey},
            AbeScheme, AsBytes, Gpsw,
        },
    },
    interfaces::{
        hybrid_crypto::{
            decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_header, ClearTextHeader,
            EncryptedHeader,
        },
        policy::{Attributes, Policy},
    },
};

type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;
type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;

fn create_test_policy() -> Policy {
    //
    // Policy settings
    //
    // let policy = Policy::new(100);
    Policy::new(100)
        .add_axis(
            "Security Level",
            &["Protected", "Confidential", "Top Secret"],
            true,
        )
        .unwrap()
        .add_axis("Department", &["R&D", "HR", "MKG", "FIN"], false)
        .unwrap()
}

#[wasm_bindgen_test]
fn test_generate_keys() {
    //
    // Policy settings
    //
    let policy = create_test_policy();
    let serialized_policy = serde_json::to_vec(&policy).unwrap();

    //
    // Generate master keys
    let master_keys =
        webassembly_generate_master_keys(Uint8Array::from(serialized_policy.as_slice())).unwrap();

    let master_keys_vec = master_keys.to_vec();
    let private_key_size = u32::from_be_bytes(master_keys_vec[0..4].try_into().unwrap());
    let private_key_bytes = &master_keys_vec[4..4 + private_key_size as usize];

    //
    // Check deserialization
    GpswMasterPrivateKey::<Bls12_381>::from_bytes(private_key_bytes).unwrap();
    GpswMasterPublicKey::<Bls12_381>::from_bytes(&master_keys_vec[4 + private_key_size as usize..])
        .unwrap();

    //
    // Generate user private key
    webassembly_generate_user_private_key(
        Uint8Array::from(private_key_bytes),
        "Department::FIN && Security Level::Top Secret",
        Uint8Array::from(serialized_policy.as_slice()),
    )
    .unwrap();
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
        Some(meta_data),
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
    let user_decryption_key_js = Uint8Array::from(user_decryption_key_bytes.as_slice());
    let encrypted_header_js = Uint8Array::from(encrypted_header.encrypted_header_bytes.as_slice());

    let cleartext_header_bytes =
        webassembly_decrypt_hybrid_header(user_decryption_key_js, encrypted_header_js).unwrap();
    let _cleartext_header =
        ClearTextHeader::<Aes256GcmCrypto>::from_bytes(&cleartext_header_bytes.to_vec()[..])
            .unwrap();
}

#[wasm_bindgen_test]
pub fn test_non_reg_decrypt_hybrid_block() {
    let symmetric_key_bytes =
        hex::decode("802de96f19589fbc0eb2f26705dc1ed261e9c80f2fec301ca7d0ecea3176405b").unwrap();
    let uid_bytes =
        hex::decode("cd8ca2eeb654b5f39f347f4e3f91b3a15c450c1e52c40716237b4c18510f65b4").unwrap();
    let encrypted_bytes = hex::decode("e09ba17fdff90afbb18546211268b8aef6517a73b701283ab334c0720372f565c751a311c1ec09a6bbb070f8a1961ca3f048b280ea36a578a0068edea8408f3cf4ab26f5a71933dffed384ea7d33e42c16fe17a1026937a345386bb980917d6d2175a48b6d69e8322689dde0bf99cee9d2da5bbee1f29b2005725b6969021462e6608284a5135677b03d8fcce03563cc4d8988f455d27b95ef62080f4c2f18e7897636ac69e9d216668765d2025f66c805d549c4ef779c32ac3286bee8d35c1b758b51f1686d2aea996cc1f3bfff2aea7d605cce963e5bc69f77f284a1c05b803df08fcdec6a6d4f0c74ad8f6076d9ca692642dcdff64a34d1fbbb4d57aea776ce8032b03d63c9e376377fb95725b6d3ac6be3a29f47d15eb22b5c81bf6168785844da8d22914076415957d9e253142f14c5c68fbe1108d74832e2347425f89b46321ac0c7b939f793e3c39e5dbb83d9e6be29db4aa3df0e645cc859aac9a0324d546b70856e2ae89c77b87a8e25eac90f9265642bbd8c407f0aa307aef613bd79fa8fd6c959c959007791621e5fe047edfcadae2c195bb681b6621a9583c8d51911e39df50331b495b603fbf826eebeffe26cd2bc0287a280801bc54cfa9fed1279a58843bb8ea1262982753481dc61852cca49279d0de5e287f6a43dca38").unwrap();

    let symmetric_key_js = Uint8Array::from(symmetric_key_bytes.as_slice());
    let uid_js = Uint8Array::from(uid_bytes.as_slice());
    let encrypted_js = Uint8Array::from(encrypted_bytes.as_slice());

    webassembly_decrypt_hybrid_block(symmetric_key_js, Some(uid_js), Some(0), encrypted_js)
        .unwrap();
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
    let policy_js = Uint8Array::from(policy_bytes.as_slice());
    let public_key_js = Uint8Array::from(public_key_bytes.as_slice());
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
        <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(symmetric_key_bytes.clone()).unwrap();

    let symmetric_key_js = Uint8Array::from(symmetric_key_bytes.as_slice());
    let uid_js = Uint8Array::from(uid_bytes.as_slice());
    let data_js = Uint8Array::from([1, 2, 3, 4, 5, 6, 7, 8].as_slice());

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
