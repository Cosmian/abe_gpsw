use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
};

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, AsBytes, Gpsw},
        policy::{Attribute, Policy},
    },
    ffi_bail, ffi_not_null, ffi_unwrap,
    interfaces::{
        ffi::error::{set_last_error, FfiError},
        hybrid_crypto::{
            self, decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_block,
            encrypt_hybrid_header, ClearTextHeader,
        },
    },
};
use cosmian_crypto_base::symmetric_crypto::Key;
use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
};

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_encrypt_header(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    header_bytes_ptr: *mut c_char,
    header_bytes_len: *mut c_int,
    policy_ptr: *const c_char,
    public_key_ptr: *const c_char,
    public_key_len: c_int,
    attributes_ptr: *const c_char,
    uid_ptr: *const c_char,
    uid_len: c_int,
    additional_data_ptr: *const c_char,
    additional_data_len: c_int,
) -> c_int {
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric key pointer should point to pre-allocated memory"
    );
    if *symmetric_key_len == 0 {
        ffi_bail!("The symmetric key buffer should have a size greater than zero");
    }
    ffi_not_null!(
        header_bytes_ptr,
        "Header bytes pointer should point to pre-allocated memory"
    );
    if *header_bytes_len == 0 {
        ffi_bail!("The header bytes buffer should have a size greater than zero");
    }
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");
    ffi_not_null!(public_key_ptr, "Policy pointer should not be null");
    if public_key_len == 0 {
        ffi_bail!("The public key should not be empty");
    }
    ffi_not_null!(attributes_ptr, "Attributes pointer should not be null");

    // Policy
    let policy = match CStr::from_ptr(policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "Hybrid Cipher: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let policy: Policy = ffi_unwrap!(serde_json::from_str(&policy));

    // Public Key
    let public_key_bytes =
        std::slice::from_raw_parts(public_key_ptr as *const u8, public_key_len as usize);
    let public_key = ffi_unwrap!(PublicKey::from_bytes(public_key_bytes));

    // Attributes
    let attributes = match CStr::from_ptr(attributes_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "Hybrid Cipher: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let attributes: Vec<Attribute> = ffi_unwrap!(serde_json::from_str(&attributes));

    // UID
    let uid = if uid_ptr.is_null() || uid_len == 0 {
        vec![]
    } else {
        std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec()
    };

    // additional data
    let additional_data = if additional_data_ptr.is_null() || additional_data_len == 0 {
        None
    } else {
        Some(
            std::slice::from_raw_parts(
                additional_data_ptr as *const u8,
                additional_data_len as usize,
            )
            .to_vec(),
        )
    };

    let meta_data = Metadata {
        uid,
        additional_data,
    };

    let encrypted_header = ffi_unwrap!(encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &attributes,
        meta_data
    ));

    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = encrypted_header.symmetric_key.as_bytes();
    let len = symmetric_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr as *mut u8, len)
        .copy_from_slice(&symmetric_key_bytes);
    *symmetric_key_len = len as c_int;

    let allocated = *header_bytes_len;
    let len = encrypted_header.encrypted_header_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(header_bytes_ptr as *mut u8, len)
        .copy_from_slice(&encrypted_header.encrypted_header_bytes);
    *header_bytes_len = len as c_int;

    0
}

#[no_mangle]
/// Decrypt n encrypted header returning the symmetric key,
/// the uid and additional data if available.
///
/// No additional data will be returned if the `additional_data_ptr` is NULL.
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_header(
    symmetric_key_ptr: *mut c_char,
    symmetric_key_len: *mut c_int,
    uid_ptr: *mut c_char,
    uid_len: *mut c_int,
    additional_data_ptr: *mut c_char,
    additional_data_len: *mut c_int,
    encrypted_header_ptr: *const c_char,
    encrypted_header_len: c_int,
    user_decryption_key_ptr: *const c_char,
    user_decryption_key_len: c_int,
) -> c_int {
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric key pointer should point to pre-allocated memory"
    );
    if *symmetric_key_len == 0 {
        ffi_bail!("The symmetric key buffer should have a size greater than zero");
    }
    ffi_not_null!(
        encrypted_header_ptr,
        "Encrypted header bytes pointer should not be bull"
    );
    if encrypted_header_len == 0 {
        ffi_bail!("The encrypted header bytes size should be greater than zero");
    }
    ffi_not_null!(
        user_decryption_key_ptr,
        "The user decryption key pointer should not be null"
    );
    if user_decryption_key_len == 0 {
        ffi_bail!("The user decryption key should not be empty");
    }

    let encrypted_header_bytes = std::slice::from_raw_parts(
        encrypted_header_ptr as *const u8,
        encrypted_header_len as usize,
    );

    let user_decryption_key_bytes = std::slice::from_raw_parts(
        user_decryption_key_ptr as *const u8,
        user_decryption_key_len as usize,
    );
    let user_decryption_key = ffi_unwrap!(UserDecryptionKey::from_bytes(user_decryption_key_bytes));

    let header: ClearTextHeader<Aes256GcmCrypto> =
        ffi_unwrap!(decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
            &user_decryption_key,
            encrypted_header_bytes
        ));

    // Symmetric Key
    let allocated = *symmetric_key_len;
    let symmetric_key_bytes = header.symmetric_key.as_bytes();
    let len = symmetric_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr as *mut u8, len)
        .copy_from_slice(&symmetric_key_bytes);
    *symmetric_key_len = len as c_int;

    // UID - if expected
    if !uid_ptr.is_null() && *uid_len > 0 {
        let allocated = *uid_len;
        let uid_bytes = &header.meta_data.uid;
        let len = uid_bytes.len();
        if (allocated as usize) < len {
            ffi_bail!(
                "The pre-allocated uid buffer is too small; need {} bytes",
                len
            );
        }
        std::slice::from_raw_parts_mut(uid_ptr as *mut u8, len).copy_from_slice(uid_bytes);
        *uid_len = len as c_int;
    }

    // additional data - if expected
    if !additional_data_ptr.is_null() && *additional_data_len > 0 {
        let allocated = *additional_data_len;
        let additional_data_bytes = &header.meta_data.additional_data;
        if let Some(ad) = additional_data_bytes {
            let len = ad.len();
            if (allocated as usize) < len {
                ffi_bail!(
                    "The pre-allocated additional_data buffer is too small; need {} bytes",
                    len
                );
            }
            std::slice::from_raw_parts_mut(additional_data_ptr as *mut u8, len).copy_from_slice(ad);
            *additional_data_len = len as c_int;
        } else {
            *additional_data_len = 0_i32;
        }
    }

    0
}

// maximum clear text size that can be safely encrypted with AES GCM (using a a single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_symmetric_encryption_overhead() -> c_int {
    hybrid_crypto::symmetric_encryption_overhead::<Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>() as c_int
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_encrypt_block(
    encrypted_ptr: *mut c_char,
    encrypted_len: *mut c_int,
    symmetric_key_ptr: *const c_char,
    symmetric_key_len: c_int,
    uid_ptr: *const c_char,
    uid_len: c_int,
    block_number: c_int,
    data_ptr: *const c_char,
    data_len: c_int,
) -> c_int {
    ffi_not_null!(
        encrypted_ptr,
        "The encrypted bytes pointer should point to pre-allocated memory"
    );
    if *encrypted_len == 0 {
        ffi_bail!("The encrypted bytes buffer should have a size greater than zero");
    }

    // Symmetric Key
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric Key pointer should not be null"
    );
    if symmetric_key_len == 0 {
        ffi_bail!("The Symmetric Key should not be empty");
    }
    let symmetric_key =
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec();

    // UID
    let uid = if !uid_ptr.is_null() && uid_len > 0 {
        std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec()
    } else {
        vec![]
    };

    // Data
    ffi_not_null!(data_ptr, "Data pointer should not be null");
    if data_len == 0 {
        ffi_bail!("The data should not be empty");
    }
    let data = std::slice::from_raw_parts(data_ptr as *const u8, data_len as usize).to_vec();

    let symmetric_key = ffi_unwrap!(<Aes256GcmCrypto as SymmetricCrypto>::Key::parse(
        symmetric_key
    ));
    let encrypted_block = ffi_unwrap!(encrypt_hybrid_block::<
        Gpsw<Bls12_381>,
        Aes256GcmCrypto,
        MAX_CLEAR_TEXT_SIZE,
    >(&symmetric_key, &uid, block_number as usize, &data));

    let allocated = *encrypted_len;
    let len = encrypted_block.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated encrypted bytes buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(encrypted_ptr as *mut u8, len).copy_from_slice(&encrypted_block);
    *encrypted_len = len as c_int;

    0
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn h_aes_decrypt_block(
    clear_text_ptr: *mut c_char,
    clear_text_len: *mut c_int,
    symmetric_key_ptr: *const c_char,
    symmetric_key_len: c_int,
    uid_ptr: *const c_char,
    uid_len: c_int,
    block_number: c_int,
    encrypted_bytes_ptr: *const c_char,
    encrypted_bytes_len: c_int,
) -> c_int {
    ffi_not_null!(
        clear_text_ptr,
        "The clear text bytes pointer should point to pre-allocated memory"
    );
    if *clear_text_len == 0 {
        ffi_bail!("The clear text bytes buffer should have a size greater than zero");
    }

    // Symmetric Key
    ffi_not_null!(
        symmetric_key_ptr,
        "Symmetric Key pointer should not be null"
    );
    if symmetric_key_len == 0 {
        ffi_bail!("The Symmetric Key should not be empty");
    }
    let symmetric_key =
        std::slice::from_raw_parts(symmetric_key_ptr as *const u8, symmetric_key_len as usize)
            .to_vec();

    // UID
    let uid = if !uid_ptr.is_null() && uid_len > 0 {
        std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec()
    } else {
        vec![]
    };

    // Data
    ffi_not_null!(encrypted_bytes_ptr, "Data pointer should not be null");
    if encrypted_bytes_len == 0 {
        ffi_bail!("The data should not be empty");
    }
    let data = std::slice::from_raw_parts(
        encrypted_bytes_ptr as *const u8,
        encrypted_bytes_len as usize,
    )
    .to_vec();

    let symmetric_key = ffi_unwrap!(<Aes256GcmCrypto as SymmetricCrypto>::Key::parse(
        symmetric_key
    ));
    let encrypted_block = ffi_unwrap!(decrypt_hybrid_block::<
        Gpsw<Bls12_381>,
        Aes256GcmCrypto,
        MAX_CLEAR_TEXT_SIZE,
    >(&symmetric_key, &uid, block_number as usize, &data));

    let allocated = *clear_text_len;
    let len = encrypted_block.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated clear text buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(clear_text_ptr as *mut u8, len)
        .copy_from_slice(&encrypted_block);
    *clear_text_len = len as c_int;

    0
}
