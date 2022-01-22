use std::{
    cell::RefCell,
    ffi::{CStr, CString},
};

use libc::{c_char, c_int};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FfiError {
    #[error("Invalid NULL pointer passed for: {0}")]
    NullPointer(String),

    #[error("FFI error: {0}")]
    Generic(String),
}

/// Return early with an error if a pointer is null
///
/// This macro is equivalent to
///  `
/// if ptr.is_null() {
///     set_last_error(FfiError::NullPointer($msg));
///     return 1;
/// }
/// `.
#[macro_export]
macro_rules! ffi_not_null {
    ($ptr:expr, $msg:literal $(,)?) => {
        if $ptr.is_null() {
            $crate::ffi::error::set_last_error($crate::ffi::error::FfiError::NullPointer(
                $msg.to_owned(),
            ));
            return 1_i32
        }
    };
}

/// Unwrap a `std::result::Result`
///
/// If the result is in error, set the last error to its error and return 1
#[macro_export]
macro_rules! ffi_unwrap {
    ($result:expr, $msg:literal $(,)?) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                set_last_error(FfiError::Generic(format!("{}: {}", $msg, e)));
                return 1_i32
            }
        }
    };
}

/// Return early with an `FfiError::Generic` error if a condition is not
/// satisfied.
#[macro_export]
macro_rules! ffi_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            $crate::ffi::error::set_last_error($crate::ffi::error::FfiError::Generic($msg.to_owned()));
            return 1_i32;
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            $crate::ffi::error::set_last_error($crate::ffi::error::FfiError::Generic($err.to_string()));
            return 1_i32;
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::ffi::error::set_last_error($crate::ffi::error::FfiError::Generic(format!($fmt, $($arg)*)));
            return 1_i32;
        }
    };
}

/// Construct a generic error from a string, an ` Error` or an fmt expression.
#[macro_export]
macro_rules! ffi_error {
    ($msg:literal $(,)?) => {
        $crate::ffi::error::FfiError::Generic($msg.to_owned())
    };
    ($err:expr $(,)?) => ({
        $crate::ffi::error::FfiError::Generic($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::ffi::error::FfiError::Generic(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! ffi_bail {
    ($msg:literal $(,)?) => {
        $crate::ffi::error::set_last_error($crate::ffi::error::FfiError::Generic($msg.to_owned()));
        return 1_i32;
    };
    ($err:expr $(,)?) => {
        $crate::ffi::error::set_last_error($crate::ffi::error::FfiError::Generic($err.to_string()));
        return 1_i32;
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::ffi::error::set_last_error($crate::ffi::error::FfiError::Generic(format!($fmt, $($arg)*)));
        return 1_i32;
    };
}

thread_local! {
    /// a thread-local variable which holds the most recent error
    static LAST_ERROR: RefCell<Option<Box<FfiError>>> = RefCell::new(None);
}

/// Set the most recent error, clearing whatever may have been there before.
pub(crate) fn set_last_error(err: FfiError) {
    eprintln!("{}", err);
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(Box::new(err));
    });
}

/// Externally set the last error recorded on the Rust side
///
/// # Safety
/// This function is meant to be called from the Foreign Function
/// Interface
#[no_mangle]
pub unsafe extern "C" fn set_error(error_message_ptr: *const c_char) -> i32 {
    ffi_not_null!(error_message_ptr, "error message");
    let error_message = match CStr::from_ptr(error_message_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(_e) => {
            set_last_error(FfiError::Generic(
                "sse_client_update: invalid error message".to_owned(),
            ));
            return 1
        }
    };
    set_last_error(FfiError::Generic(error_message));
    0
    //
}

/// Get the most recent error as utf-8 bytes, clearing it in the process.
/// # Safety
/// - `error_msg`: must be pre-allocated with a sufficient size
#[no_mangle]
pub unsafe extern "C" fn get_last_error(error_msg: *mut c_char, error_len: *mut c_int) -> c_int {
    if error_msg.is_null() {
        eprintln!("get_last_error: must pass a pre-allocated buffer");
        return 1
    }
    if error_len.is_null() {
        eprintln!("get_last_error: must pass a pre-allocated len with the max buffer length");
        return 1
    }
    if *error_len < 1 {
        eprintln!("get_last_error: the buffer must be at leas one byte long");
        return 1
    }
    let err = LAST_ERROR.with(|prev| prev.borrow_mut().take());

    // Build a CString that will cleanup NULL bytes in the middle if needed
    let cs = ffi_unwrap!(
        CString::new(err.map_or("".to_string(), |e| e.to_string())),
        "failed to convert error to CString"
    );
    // leave a space for a null byte at the end if the string exceeds the buffer
    // size
    let bytes = cs.as_bytes();
    let chunk = if bytes.len() > (*error_len - 1) as usize {
        &bytes[0..(*error_len - 1) as usize]
    } else {
        bytes
    };
    // strncpy will the remaining space with NULL
    libc::strncpy(
        error_msg,
        chunk.as_ptr() as *const c_char,
        *error_len as usize,
    );
    // The actual bytes size, not taking into accourt the final NULL
    *error_len = std::cmp::min(*error_len - 1, chunk.len() as i32);
    0
}
