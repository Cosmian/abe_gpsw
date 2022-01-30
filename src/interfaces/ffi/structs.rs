// ---------------------------------------
// //TODO This creates strange SIGSEGV on destroy and is de-activated for now
// ---------------------------------------

type Cipher = HybridCipher<Gpsw<Bls12_381>, Aes256GcmCrypto>;

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
        uid,
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
    // will be dropped here
}
