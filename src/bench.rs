// Benchmarks
// TL;DR; run
//   cargo run --release --features interfaces --bin bench_abe_gpsw -- --help
// for online help

use std::env;

#[cfg(feature = "ffi")]
use {
    abe_gpsw::interfaces::ffi::{
        error::get_last_error,
        hybrid_gpsw_aes::{
            h_aes_create_decryption_cache, h_aes_create_encryption_cache, h_aes_decrypt_header,
            h_aes_decrypt_header_using_cache, h_aes_destroy_decryption_cache,
            h_aes_destroy_encryption_cache, h_aes_encrypt_header, h_aes_encrypt_header_using_cache,
        },
    },
    std::{
        ffi::{CStr, CString},
        os::raw::c_int,
    },
};
#[cfg(feature = "interfaces")]
use {
    abe_gpsw::{
        core::{
            bilinear_map::bls12_381::Bls12_381,
            gpsw::{AbeScheme, AsBytes, Gpsw},
            policy::{attr, Policy},
        },
        interfaces::hybrid_crypto::{
            decrypt_hybrid_header, encrypt_hybrid_header, EncryptedHeader,
        },
    },
    cosmian_crypto_base::{
        hybrid_crypto::Metadata, symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
    },
};
#[cfg(any(feature = "interfaces", feature = "ffi"))]
use {serde_json::Value, std::time::Instant};

#[cfg(feature = "interfaces")]
type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;

#[cfg(feature = "interfaces")]
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

#[allow(clippy::if_same_then_else)]
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    let selector = if args.len() < 2 { "all" } else { &args[1] };
    if selector != "--help" {
        println!(
            "Bench selector: {}. Run with --help as parameter for details",
            selector
        );
    }
    if selector == "header_encryption" {
        #[cfg(feature = "interfaces")]
        bench_header_encryption()?;
    } else if selector == "ffi_header_encryption" {
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_encryption()?;
        }
    } else if selector == "ffi_header_enc_using_cache" {
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_encryption_using_cache()?;
        }
    } else if selector == "header_decryption" {
        #[cfg(feature = "interfaces")]
        bench_header_decryption()?;
    } else if selector == "ffi_header_decryption" {
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_decryption()?;
        }
    } else if selector == "ffi_header_dec_using_cache" {
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_decryption_using_cache()?;
        }
    } else if selector == "all" {
        #[cfg(feature = "interfaces")]
        bench_header_encryption()?;
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_encryption()?;
            bench_ffi_header_encryption_using_cache()?;
        }
        #[cfg(feature = "interfaces")]
        bench_header_decryption()?;
        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_decryption()?;
            bench_ffi_header_decryption_using_cache()?;
        }
    } else {
        println!(
            r#"
Usage: cargo run --release --features ffi --bin bench_abe_gpsw -- [OPTION]
where [OPTION] is:

all                        : (or none) run all benches
header_encryption          : reference hybrid header encryption
ffi_header_encryption      : hybrid header encryption via FFI
ffi_header_enc_using_cache : hybrid header encryption via FFI using a cache
header_decryption          : reference hybrid header decryption
ffi_header_decryption      : hybrid header decryption via FFI
ffi_header_dec_using_cache : hybrid header decryption via FFI using a cache


To generate a flame graph:
--------------------------
1. Install cargo flamegraph: https://github.com/flamegraph-rs/flamegraph
2. On Linux, you will probably need to set these values in /etc/sysctl.conf and reboot
        kernel.perf_event_paranoid=-1
        kernel.kptr_restrict=0
3. Then generate the flamegraph SVG using

        CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --features ffi --bin bench_abe_gpsw -- OPTION

see above for the OPTION values
"#
        )
    }
    Ok(())
}

#[cfg(feature = "interfaces")]
pub fn bench_header_encryption() -> anyhow::Result<()> {
    print!("Running 'direct' header encryption...");
    let public_key_json: Value = serde_json::from_str(include_str!(
        "./interfaces/hybrid_crypto/tests/public_master_key.json"
    ))?;
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = key_value[0]["value"].as_str().unwrap();
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
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };
    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        let _encrypted_header = encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
            &policy,
            &public_key,
            &policy_attributes,
            meta_data.clone(),
        )?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}

#[cfg(feature = "interfaces")]
fn generate_encrypted_header() -> anyhow::Result<EncryptedHeader<Aes256GcmCrypto>> {
    let public_key_json: Value = serde_json::from_str(include_str!(
        "./interfaces/hybrid_crypto/tests/public_master_key.json"
    ))?;
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = key_value[0]["value"].as_str().unwrap();
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
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &policy_attributes,
        meta_data,
    )
}

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_encryption() -> anyhow::Result<()> {
    print!("Running 'FFI' header encryption...");
    let public_key_json: Value = serde_json::from_str(include_str!(
        "./interfaces/hybrid_crypto/tests/public_master_key.json"
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
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr().cast::<i8>();
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key.as_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let attributes_json = CString::new(serde_json::to_string(&policy_attributes)?.as_str())?;
    let attributes_ptr = attributes_json.as_ptr();

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        unwrap_ffi_error(h_aes_encrypt_header(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            header_bytes_ptr,
            &mut header_bytes_len,
            policy_ptr,
            public_key_ptr.cast::<i8>(),
            public_key_len,
            attributes_ptr,
            meta_data.uid.as_ptr().cast::<i8>(),
            meta_data.uid.len() as i32,
            meta_data
                .additional_data
                .as_ref()
                .unwrap()
                .as_ptr()
                .cast::<i8>(),
            meta_data.additional_data.as_ref().unwrap().len() as i32,
        ))?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_encryption_using_cache() -> anyhow::Result<()> {
    print!("Running 'FFI' header encryption using cache...");
    let public_key_json: Value = serde_json::from_str(include_str!(
        "./interfaces/hybrid_crypto/tests/public_master_key.json"
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

    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key.as_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr().cast::<i8>();
    let public_key_len = public_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;
    unwrap_ffi_error(h_aes_create_encryption_cache(
        &mut cache_handle,
        policy_ptr,
        public_key_ptr,
        public_key_len,
    ))?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr().cast::<i8>();
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let attributes_json = CString::new(serde_json::to_string(&policy_attributes)?.as_str())?;
    let attributes_ptr = attributes_json.as_ptr();

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        unwrap_ffi_error(h_aes_encrypt_header_using_cache(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            header_bytes_ptr,
            &mut header_bytes_len,
            cache_handle,
            attributes_ptr,
            meta_data.uid.as_ptr().cast::<i8>(),
            meta_data.uid.len() as i32,
            meta_data
                .additional_data
                .as_ref()
                .unwrap()
                .as_ptr()
                .cast::<i8>(),
            meta_data.additional_data.as_ref().unwrap().len() as i32,
        ))?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    unwrap_ffi_error(h_aes_destroy_encryption_cache(cache_handle))?;
    Ok(())
}

///
/// # Safety
#[cfg(feature = "interfaces")]
pub fn bench_header_decryption() -> anyhow::Result<()> {
    print!("Running direct header decryption...");
    let encrypted_header = generate_encrypted_header()?;

    let user_decryption_key_json: Value = serde_json::from_str(include_str!(
        "./interfaces/hybrid_crypto/tests/fin_confidential_user_key.json"
    ))?;
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let user_decryption_key = UserDecryptionKey::from_bytes(&hex::decode(hex_key)?)?;

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        let _header_ = decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
            &user_decryption_key,
            &encrypted_header.encrypted_header_bytes,
        )?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_decryption() -> anyhow::Result<()> {
    print!("Running FFI header decryption...");
    let encrypted_header = generate_encrypted_header()?;

    let user_decryption_key_json: Value = serde_json::from_str(include_str!(
        "./interfaces/hybrid_crypto/tests/fin_confidential_user_key.json"
    ))?;
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let user_decryption_key = UserDecryptionKey::from_bytes(&hex::decode(hex_key)?)?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr().cast::<i8>();
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key.as_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        unwrap_ffi_error(h_aes_decrypt_header(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            uid_ptr,
            &mut uid_len,
            additional_data_ptr,
            &mut additional_data_len,
            encrypted_header
                .encrypted_header_bytes
                .as_ptr()
                .cast::<i8>(),
            encrypted_header.encrypted_header_bytes.len() as c_int,
            user_decryption_key_ptr,
            user_decryption_key_len,
        ))?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_decryption_using_cache() -> anyhow::Result<()> {
    print!("Running FFI header decryption using cache...");
    let encrypted_header = generate_encrypted_header()?;

    let user_decryption_key_json: Value = serde_json::from_str(include_str!(
        "./interfaces/hybrid_crypto/tests/fin_confidential_user_key.json"
    ))?;
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let user_decryption_key = UserDecryptionKey::from_bytes(&hex::decode(hex_key)?)?;

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr().cast::<i8>();
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key.as_bytes()?;
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;

    unwrap_ffi_error(h_aes_create_decryption_cache(
        &mut cache_handle,
        user_decryption_key_ptr,
        user_decryption_key_len,
    ))?;

    let loops = 5000;
    let before = Instant::now();
    for _i in 0..loops {
        unwrap_ffi_error(h_aes_decrypt_header_using_cache(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            uid_ptr,
            &mut uid_len,
            additional_data_ptr,
            &mut additional_data_len,
            encrypted_header
                .encrypted_header_bytes
                .as_ptr()
                .cast::<i8>(),
            encrypted_header.encrypted_header_bytes.len() as c_int,
            cache_handle,
        ))?;
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    unwrap_ffi_error(h_aes_destroy_decryption_cache(cache_handle))?;

    Ok(())
}

#[cfg(feature = "ffi")]
unsafe fn unwrap_ffi_error(val: i32) -> anyhow::Result<()> {
    if val != 0 {
        let mut message_bytes_key = vec![0u8; 4096];
        let message_bytes_ptr = message_bytes_key.as_mut_ptr().cast::<i8>();
        let mut message_bytes_len = message_bytes_key.len() as c_int;
        get_last_error(message_bytes_ptr, &mut message_bytes_len);
        let cstr = CStr::from_ptr(message_bytes_ptr);
        anyhow::bail!("ERROR: {}", cstr.to_str()?);
    } else {
        Ok(())
    }
}
