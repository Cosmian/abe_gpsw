use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
};

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{scheme::GpswMasterPrivateKey, AsBytes, Gpsw},
        Engine,
    },
    ffi_bail, ffi_not_null, ffi_unwrap,
    interfaces::{
        ffi::error::{set_last_error, FfiError},
        policy::{AccessPolicy, Policy},
    },
};

#[no_mangle]
/// Generate the master authority keys for supplied Policy
///
///  - `master_keys_ptr`    : Output buffer containing both master keys
///  - `master_keys_len`    : Size of the output buffer
///  - `policy_ptr`         : Policy to use to generate the keys
/// # Safety
pub unsafe extern "C" fn h_generate_master_keys(
    master_keys_ptr: *mut c_char,
    master_keys_len: *mut c_int,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        master_keys_ptr,
        "Master keys pointer should point to pre-allocated memory"
    );
    if *master_keys_len == 0 {
        ffi_bail!("The master keys buffer should have a size greater than zero");
    }

    ffi_not_null!(policy_ptr, "Policy pointer should not be null");

    //
    // Policy
    let policy = match CStr::from_ptr(policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "ABE keys generation: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let policy: Policy = ffi_unwrap!(serde_json::from_str(&policy));

    //
    // Generate master keys
    let (private_key, public_key, _) =
        ffi_unwrap!(Engine::<Gpsw<Bls12_381>>::new().generate_master_key(&policy));

    //
    // Serialize master keys
    let private_keys_bytes = ffi_unwrap!(private_key.as_bytes());
    let public_keys_bytes = ffi_unwrap!(public_key.as_bytes());

    let mut master_keys_bytes =
        Vec::<u8>::with_capacity(4 + private_keys_bytes.len() + public_keys_bytes.len());
    master_keys_bytes.extend_from_slice(&u32::to_be_bytes(private_keys_bytes.len() as u32));
    master_keys_bytes.extend_from_slice(&private_keys_bytes);
    master_keys_bytes.extend_from_slice(&public_keys_bytes);

    //
    // Prepare output
    let allocated = *master_keys_len;
    let len = master_keys_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated master keys buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(master_keys_ptr as *mut u8, len)
        .copy_from_slice(&master_keys_bytes);
    *master_keys_len = len as c_int;

    0
}

#[no_mangle]
/// Generate the user private key matching the given access policy
///
/// - `user_private_key_ptr`: Output buffer containing user private key
/// - `user_private_key_len`: Size of the output buffer
/// - `master_private_key_ptr`: Master private key (required for this
///   generation)
/// - `master_private_key_len`: Master private key length
/// - `access_policy_ptr`: Access policy of the user private key (JSON)
/// - `policy_ptr`: Policy to use to generate the keys (JSON)
/// # Safety
pub unsafe extern "C" fn h_generate_user_private_key(
    user_private_key_ptr: *mut c_char,
    user_private_key_len: *mut c_int,
    master_private_key_ptr: *const c_char,
    master_private_key_len: c_int,
    access_policy_ptr: *const c_char,
    policy_ptr: *const c_char,
) -> c_int {
    //
    // Checks inputs
    ffi_not_null!(
        user_private_key_ptr,
        "User private key pointer should point to pre-allocated memory"
    );
    if *user_private_key_len == 0 {
        ffi_bail!("The user private key buffer should have a size greater than zero");
    }
    ffi_not_null!(
        master_private_key_ptr,
        "Master private key pointer should not be null"
    );
    if master_private_key_len == 0 {
        ffi_bail!("The master private key should not be empty");
    }
    ffi_not_null!(
        access_policy_ptr,
        "Access Policy pointer should not be null"
    );
    ffi_not_null!(policy_ptr, "Policy pointer should not be null");

    //
    // Master private key deserialization
    let master_private_key_bytes = std::slice::from_raw_parts(
        master_private_key_ptr as *const u8,
        master_private_key_len as usize,
    );
    let master_private_key = ffi_unwrap!(GpswMasterPrivateKey::<Bls12_381>::from_bytes(
        master_private_key_bytes
    ));

    //
    // Access Policy
    let access_policy = match CStr::from_ptr(access_policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "ABE keys generation: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let access_policy: AccessPolicy = ffi_unwrap!(serde_json::from_str(&access_policy));

    //
    // Policy
    let policy = match CStr::from_ptr(policy_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "ABE keys generation: invalid Policy".to_owned(),
            ));
            return 1;
        }
    };
    let policy: Policy = ffi_unwrap!(serde_json::from_str(&policy));

    //
    // Generate master keys
    let user_key = ffi_unwrap!(Engine::<Gpsw<Bls12_381>>::new().generate_user_key(
        &policy,
        &master_private_key,
        &access_policy
    ));

    //
    // Serialize user private key
    let user_key_bytes = ffi_unwrap!(user_key.as_bytes());

    //
    // Prepare output
    let allocated = *user_private_key_len;
    let len = user_key_bytes.len();
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated user private key buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(user_private_key_ptr as *mut u8, len)
        .copy_from_slice(&user_key_bytes);
    *user_private_key_len = len as c_int;

    0
}