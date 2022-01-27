pub mod error;
use std::ffi::CStr;

use crate::interfaces::hybrid_crypto::{self, encrypt_hybrid_block, HybridCipher};
use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{abe::Gpsw, AbeScheme, AsBytes},
        policy::{Attribute, Policy},
    },
    ffi_bail, ffi_not_null, ffi_unwrap,
    interfaces::{
        ffi::error::{set_last_error, FfiError},
        hybrid_crypto::encrypt_hybrid_header,
    },
};
use cosmian_crypto_base::symmetric_crypto::Key;
use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
};
use libc::{c_char, c_int, c_void};

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn encrypt_header(
    symmetric_key_ptr: *mut c_void,
    symmetric_key_len: *mut c_int,
    header_bytes_ptr: *mut c_void,
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
    ffi_not_null!(uid_ptr, "UID pointer should not be null");
    if uid_len == 0 {
        ffi_bail!("The UID should not be empty");
    }

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
    // println!("AttrIbutes: {:?}", attributes);

    // UID
    let uid = std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec();

    // additional data
    let additional_data = if additional_data_ptr.is_null() {
        vec![]
    } else {
        std::slice::from_raw_parts(
            additional_data_ptr as *const u8,
            additional_data_len as usize,
        )
        .to_vec()
    };

    let meta_data = Metadata {
        sec: uid,
        additional_data,
    };

    let encrypted_header = ffi_unwrap!(encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        policy,
        public_key,
        &attributes,
        meta_data
    ));

    let allocated = *symmetric_key_len;
    let len = encrypted_header.symmetric_key.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(symmetric_key_ptr as *mut u8, len)
        .copy_from_slice(&encrypted_header.symmetric_key);
    *symmetric_key_len = len as c_int;

    let allocated = *header_bytes_len;
    let len = encrypted_header.header_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(header_bytes_ptr as *mut u8, len)
        .copy_from_slice(&encrypted_header.header_bytes);
    *header_bytes_len = len as c_int;

    0
}

// maximum clear text size that can be safely encrypted with AES GCM (using a a single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn symmetric_encryption_overhead() -> c_int {
    hybrid_crypto::symmetric_encryption_overhead::<Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>() as c_int
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn encrypt_block(
    encrypted_ptr: *mut c_void,
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
        "Header bytes pointer should point to pre-allocated memory"
    );
    if *encrypted_len == 0 {
        ffi_bail!("The header bytes buffer should have a size greater than zero");
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
    ffi_not_null!(uid_ptr, "UID pointer should not be null");
    if uid_len == 0 {
        ffi_bail!("The UID should not be empty");
    }
    let uid = std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec();

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
            "The pre-allocated symmetric key buffer is too small; need {} bytes",
            len
        );
    }
    std::slice::from_raw_parts_mut(encrypted_ptr as *mut u8, len).copy_from_slice(&encrypted_block);
    *encrypted_len = len as c_int;

    0
}

// ---------------------------------------
//
// ---------------------------------------

#[no_mangle]
pub extern "C" fn square(x: i32) -> i32 {
    x * x
}

type Cipher = HybridCipher<Gpsw<Bls12_381>, Aes256GcmCrypto>;
type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;

#[repr(C)]
pub struct OpaqueCipher(Box<Cipher>);

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn hybrid_cipher_new(
    cipher_ptr_ptr: *mut *mut c_void,
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
        cipher_ptr_ptr,
        "Cipher pointer to pointer should not be null"
    );
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");
    ffi_not_null!(public_key_ptr, "Policy pointer should not be null");
    ffi_not_null!(attributes_ptr, "Attributes pointer should not be null");
    ffi_not_null!(uid_ptr, "UID pointer should not be null");

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
    // println!("AttrIbutes: {:?}", attributes);

    // UID
    let uid = std::slice::from_raw_parts(uid_ptr as *const u8, uid_len as usize).to_vec();

    // additional data
    let additional_data = if additional_data_ptr.is_null() {
        vec![]
    } else {
        std::slice::from_raw_parts(
            additional_data_ptr as *const u8,
            additional_data_len as usize,
        )
        .to_vec()
    };

    let meta_data = Metadata {
        sec: uid,
        additional_data,
    };

    *cipher_ptr_ptr = std::ptr::null_mut();
    let cipher: Cipher = ffi_unwrap!(Cipher::instantiate(
        policy,
        public_key,
        &attributes,
        meta_data
    ));
    let opaque_cipher = OpaqueCipher(Box::new(cipher));
    *cipher_ptr_ptr = Box::into_raw(Box::new(opaque_cipher)) as *mut c_void;
    0
}

#[no_mangle]
///
/// # Safety
pub unsafe extern "C" fn hybrid_cipher_destroy(cipher: *mut c_void) {
    // regain control of the Cipher instance
    let opaque_cipher: Box<OpaqueCipher> = Box::from_raw(cipher as *mut OpaqueCipher);
    // TODO dropping the inner cipher seg faults for an unknown reason -Rust 1.58 and 1.60 unstable
    drop(opaque_cipher);
    println!("Cipher Dropped");
    // will be dropped here
}
