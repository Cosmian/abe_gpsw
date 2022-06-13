use std::{convert::TryFrom, ffi::CStr};

use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
};

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, AsBytes, Gpsw},
        policy::{attr, Policy},
    },
    interfaces::{ffi::error::get_last_error, hybrid_crypto::EncryptedHeader},
};

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;

type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;
use std::{
    ffi::CString,
    os::raw::{c_char, c_int},
};

use serde_json::Value;

use super::hybrid_gpsw_aes::{
    h_aes_create_decryption_cache, h_aes_create_encryption_cache, h_aes_decrypt_header,
    h_aes_decrypt_header_using_cache, h_aes_destroy_decryption_cache,
    h_aes_destroy_encryption_cache, h_aes_encrypt_header, h_aes_encrypt_header_using_cache,
};

unsafe fn encrypt_header(meta_data: &Metadata) -> anyhow::Result<EncryptedHeader<Aes256GcmCrypto>> {
    let public_key_json: Value = serde_json::from_str(include_str!(
        "../hybrid_crypto/tests/public_master_key.json"
    ))?;
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let public_key = PublicKey::from_bytes(&hex::decode(hex_key)?)?;

    // Policy
    let policy_hex = key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .unwrap();
    let policy: Policy = serde_json::from_slice(&hex::decode(policy_hex)?)?;

    let policy_attributes = vec![
        attr("Department", "FIN"),
        attr("Security Level", "Confidential"),
    ];

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut encrypted_header_bytes = vec![0u8; 4096];
    let encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr() as *mut c_char;
    let mut encrypted_header_len = encrypted_header_bytes.len() as c_int;

    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key.as_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let attributes_json = CString::new(serde_json::to_string(&policy_attributes)?.as_str())?;
    let attributes_ptr = attributes_json.as_ptr();

    unwrap_ffi_error(h_aes_encrypt_header(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        encrypted_header_ptr,
        &mut encrypted_header_len,
        policy_ptr,
        public_key_ptr as *const c_char,
        public_key_len,
        attributes_ptr,
        meta_data.uid.as_ptr() as *const c_char,
        meta_data.uid.len() as i32,
        meta_data.additional_data.as_ref().unwrap().as_ptr() as *const c_char,
        meta_data.additional_data.as_ref().unwrap().len() as i32,
    ))?;

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec(),
    )?;

    let encrypted_header_bytes_ = std::slice::from_raw_parts(
        encrypted_header_ptr as *const u8,
        encrypted_header_len as usize,
    )
    .to_vec();
    Ok(EncryptedHeader {
        symmetric_key: symmetric_key_,
        encrypted_header_bytes: encrypted_header_bytes_,
    })
}

struct DecryptedHeader {
    symmetric_key: <Aes256GcmCrypto as SymmetricCrypto>::Key,
    meta_data: Metadata,
}

unsafe fn decrypt_header(
    header: &EncryptedHeader<Aes256GcmCrypto>,
) -> anyhow::Result<DecryptedHeader> {
    let user_decryption_key_json: Value = serde_json::from_str(include_str!(
        "../hybrid_crypto/tests/fin_confidential_user_key.json"
    ))?;
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let user_decryption_key = UserDecryptionKey::from_bytes(&hex::decode(hex_key)?)?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr() as *mut c_char;
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr() as *mut c_char;
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key.as_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr() as *const c_char;
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    unwrap_ffi_error(h_aes_decrypt_header(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        uid_ptr,
        &mut uid_len,
        additional_data_ptr,
        &mut additional_data_len,
        header.encrypted_header_bytes.as_ptr() as *const c_char,
        header.encrypted_header_bytes.len() as c_int,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec(),
    )?;

    let uid_bytes_ = std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec();

    let additional_data_bytes_ = std::slice::from_raw_parts(
        additional_data_ptr as *const u8,
        additional_data_len as usize,
    )
    .to_vec();

    Ok(DecryptedHeader {
        symmetric_key: symmetric_key_,
        meta_data: Metadata {
            uid: uid_bytes_,
            additional_data: Some(additional_data_bytes_),
        },
    })
}

unsafe fn unwrap_ffi_error(val: i32) -> anyhow::Result<()> {
    if val != 0 {
        let mut message_bytes_key = vec![0u8; 4096];
        let message_bytes_ptr = message_bytes_key.as_mut_ptr() as *mut c_char;
        let mut message_bytes_len = message_bytes_key.len() as c_int;
        get_last_error(message_bytes_ptr, &mut message_bytes_len);
        let cstr = CStr::from_ptr(message_bytes_ptr);
        anyhow::bail!("ERROR: {}", cstr.to_str()?);
    } else {
        Ok(())
    }
}

unsafe fn encrypt_header_using_cache(
    meta_data: &Metadata,
) -> anyhow::Result<EncryptedHeader<Aes256GcmCrypto>> {
    let public_key_json: Value = serde_json::from_str(include_str!(
        "../hybrid_crypto/tests/public_master_key.json"
    ))?;
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let public_key = PublicKey::from_bytes(&hex::decode(hex_key)?)?;

    // Policy
    let policy_hex = key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .unwrap();
    let policy: Policy = serde_json::from_slice(&hex::decode(policy_hex)?)?;

    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key.as_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr() as *const c_char;
    let public_key_len = public_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_encryption_cache(
        &mut cache_handle,
        policy_ptr,
        public_key_ptr,
        public_key_len,
    ))?;

    let policy_attributes = vec![
        attr("Department", "FIN"),
        attr("Security Level", "Confidential"),
    ];

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut encrypted_header_bytes = vec![0u8; 4096];
    let encrypted_header_ptr = encrypted_header_bytes.as_mut_ptr() as *mut c_char;
    let mut encrypted_header_len = encrypted_header_bytes.len() as c_int;

    let attributes_json = CString::new(serde_json::to_string(&policy_attributes)?.as_str())?;
    let attributes_ptr = attributes_json.as_ptr();

    unwrap_ffi_error(h_aes_encrypt_header_using_cache(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        encrypted_header_ptr,
        &mut encrypted_header_len,
        cache_handle,
        attributes_ptr,
        meta_data.uid.as_ptr() as *const c_char,
        meta_data.uid.len() as i32,
        meta_data.additional_data.as_ref().unwrap().as_ptr() as *const c_char,
        meta_data.additional_data.as_ref().unwrap().len() as i32,
    ))?;

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec(),
    )?;

    let encrypted_header_bytes_ = std::slice::from_raw_parts(
        encrypted_header_ptr as *const u8,
        encrypted_header_len as usize,
    )
    .to_vec();

    unwrap_ffi_error(h_aes_destroy_encryption_cache(cache_handle))?;

    Ok(EncryptedHeader {
        symmetric_key: symmetric_key_,
        encrypted_header_bytes: encrypted_header_bytes_,
    })
}

unsafe fn decrypt_header_using_cache(
    header: &EncryptedHeader<Aes256GcmCrypto>,
) -> anyhow::Result<DecryptedHeader> {
    let user_decryption_key_json: Value = serde_json::from_str(include_str!(
        "../hybrid_crypto/tests/fin_confidential_user_key.json"
    ))?;
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let user_decryption_key = UserDecryptionKey::from_bytes(&hex::decode(hex_key)?)?;

    let user_decryption_key_bytes = user_decryption_key.as_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr() as *const c_char;
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_decryption_cache(
        &mut cache_handle,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr() as *mut c_char;
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr() as *mut c_char;
    let mut additional_data_len = additional_data.len() as c_int;

    unwrap_ffi_error(h_aes_decrypt_header_using_cache(
        symmetric_key_ptr,
        &mut symmetric_key_len,
        uid_ptr,
        &mut uid_len,
        additional_data_ptr,
        &mut additional_data_len,
        header.encrypted_header_bytes.as_ptr() as *const c_char,
        header.encrypted_header_bytes.len() as c_int,
        cache_handle,
    ))?;

    let symmetric_key_ = <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec(),
    )?;

    let uid_bytes_ = std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec();

    let additional_data_bytes_ = std::slice::from_raw_parts(
        additional_data_ptr as *const u8,
        additional_data_len as usize,
    )
    .to_vec();

    unwrap_ffi_error(h_aes_destroy_decryption_cache(cache_handle))?;

    Ok(DecryptedHeader {
        symmetric_key: symmetric_key_,
        meta_data: Metadata {
            uid: uid_bytes_,
            additional_data: Some(additional_data_bytes_),
        },
    })
}

#[test]
fn test_ffi_hybrid_header() -> anyhow::Result<()> {
    unsafe {
        let meta_data = Metadata {
            uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            additional_data: Some(vec![10, 11, 12, 13, 14]),
        };

        let encrypted_header = encrypt_header(&meta_data)?;
        let decrypted_header = decrypt_header(&encrypted_header)?;

        assert_eq!(
            encrypted_header.symmetric_key,
            decrypted_header.symmetric_key
        );
        assert_eq!(&meta_data.uid, &decrypted_header.meta_data.uid);
        assert_eq!(
            &meta_data.additional_data,
            &decrypted_header.meta_data.additional_data
        );
    }
    Ok(())
}

#[test]
fn test_ffi_hybrid_header_using_cache() -> anyhow::Result<()> {
    unsafe {
        let meta_data = Metadata {
            uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            additional_data: Some(vec![10, 11, 12, 13, 14]),
        };
        let encrypted_header = encrypt_header_using_cache(&meta_data)?;
        let decrypted_header = decrypt_header_using_cache(&encrypted_header)?;

        assert_eq!(
            encrypted_header.symmetric_key,
            decrypted_header.symmetric_key
        );
        assert_eq!(&meta_data.uid, &decrypted_header.meta_data.uid);
        assert_eq!(
            &meta_data.additional_data,
            &decrypted_header.meta_data.additional_data
        );
    }
    Ok(())
}
