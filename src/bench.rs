// Benchmarks
// TL;DR; run
//   cargo run --release --features interfaces --bin bench_abe_gpsw -- --help
// for online help

use std::env;
#[cfg(any(feature = "interfaces", feature = "ffi"))]
use {
    abe_gpsw::core::gpsw::AsBytes,
    abe_gpsw::core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, Gpsw},
    },
    serde_json::Value,
    std::time::Instant,
};
#[cfg(feature = "interfaces")]
use {
    abe_gpsw::core::policy::{attr, Policy},
    abe_gpsw::interfaces::hybrid_crypto::encrypt_hybrid_header,
    cosmian_crypto_base::{
        hybrid_crypto::Metadata, symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
    },
};
#[cfg(feature = "ffi")]
use {
    abe_gpsw::interfaces::ffi::{error::get_last_error, hybrid_gpsw_aes::h_aes_encrypt_header},
    std::{
        ffi::{CStr, CString},
        os::raw::{c_char, c_int},
    },
};

#[cfg(any(feature = "interfaces", feature = "ffi"))]
type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
//type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

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
    } else if selector == "all" {
        #[cfg(feature = "interfaces")]
        bench_header_encryption()?;

        #[cfg(feature = "ffi")]
        unsafe {
            bench_ffi_header_encryption()?;
        }
    } else {
        println!(
            r#"
Usage: cargo run --release --features ffi --bin bench_abe_gpsw -- [OPTION]
where [OPTION] is:

all                    : (or none) run all benches
header_encryption      : direct hybrid header encryption bench
ffi_header_encryption  : hybrid header encryption bench via FFI


To generate a flame graph
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
    print!("Running 'direct' header encryption bench...");
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

///
/// # Safety
#[cfg(feature = "ffi")]
pub unsafe fn bench_ffi_header_encryption() -> anyhow::Result<()> {
    print!("Running 'FFI' header encryption bench...");
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
    // let meta_data = Metadata {
    //     uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
    //     additional_data: Some(vec![10, 11, 12, 13, 14]),
    // };

    let mut symmetric_key = vec![0u8; 32];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr() as *mut c_char;
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr() as *mut c_char;
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let policy_cs = CString::new(serde_json::to_string(&policy)?.as_str())?;
    let policy_ptr = policy_cs.as_ptr();

    let public_key_bytes = public_key.as_bytes()?;
    let public_key_ptr = public_key_bytes.as_ptr();
    let public_key_len = public_key_bytes.len() as i32;

    let attributes_json = CString::new(serde_json::to_string(&policy_attributes)?.as_str())?;
    let attributes_ptr = attributes_json.as_ptr();

    let loops = 100;
    let before = Instant::now();
    for _i in 0..loops {
        let result = h_aes_encrypt_header(
            symmetric_key_ptr,
            &mut symmetric_key_len,
            header_bytes_ptr,
            &mut header_bytes_len,
            policy_ptr,
            public_key_ptr as *const i8,
            public_key_len,
            attributes_ptr,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
        );
        if result == 1 {
            let mut message_bytes_key = vec![0u8; 4096];
            let message_bytes_ptr = message_bytes_key.as_mut_ptr() as *mut c_char;
            let mut message_bytes_len = message_bytes_key.len() as c_int;
            get_last_error(message_bytes_ptr, &mut message_bytes_len);
            let cstr = CStr::from_ptr(message_bytes_ptr);
            anyhow::bail!("ERROR: {}", cstr.to_str()?);
        }
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time: {} micro seconds", avg_time);

    Ok(())
}
