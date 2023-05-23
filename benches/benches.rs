use cosmian_abe_gpsw::core::{
    bilinear_map::bls12_381::Bls12_381,
    gpsw::Gpsw,
    msp::Node::{self, *},
};
#[cfg(feature = "interfaces")]
use criterion::criterion_main;
use criterion::{criterion_group, Criterion};
#[cfg(feature = "ffi")]
use {
    abe_policy::Attribute,
    cosmian_abe_gpsw::{
        error::FormatErr,
        interfaces::{
            ffi::{
                error::get_last_error,
                hybrid_gpsw_aes::{
                    h_aes_create_decryption_cache, h_aes_create_encryption_cache,
                    h_aes_decrypt_header, h_aes_decrypt_header_using_cache,
                    h_aes_destroy_decryption_cache, h_aes_destroy_encryption_cache,
                    h_aes_encrypt_header, h_aes_encrypt_header_using_cache,
                },
            },
            hybrid_crypto::EncryptedHeader,
        },
    },
    cosmian_crypto_base::{
        symmetric_crypto::{Metadata, SymmetricCrypto},
        typenum::Unsigned,
        KeyTrait,
    },
    std::{
        ffi::{CStr, CString},
        os::raw::c_int,
    },
};
#[cfg(feature = "interfaces")]
use {
    abe_policy::Policy,
    cosmian_abe_gpsw::{
        core::gpsw::{AbeScheme, AsBytes},
        interfaces::hybrid_crypto::{decrypt_hybrid_header, encrypt_hybrid_header},
    },
    cosmian_crypto_base::symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
};

#[cfg(feature = "interfaces")]
type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;

#[cfg(feature = "interfaces")]
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

/// Generate encrypted header with some metadata
#[cfg(feature = "ffi")]
fn generate_encrypted_header() -> EncryptedHeader<Aes256GcmCrypto> {
    let public_key_json: serde_json::Value = serde_json::from_str(include_str!(
        "../src/interfaces/hybrid_crypto/tests/public_master_key.json"
    ))
    .expect("cannot deserialize public key JSON");
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = key_value[0]["value"]
        .as_str()
        .expect("no key as hex found in JSON");
    let public_key =
        PublicKey::try_from_bytes(&hex::decode(hex_key).expect("cannot hex decode public key"))
            .expect("cannot deserialize public key");

    // Policy
    let policy_hex = key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .expect("no policy as hex found in JSON");
    let policy: Policy =
        serde_json::from_slice(&hex::decode(policy_hex).expect("cannot hex decode policy"))
            .expect("cannot deserialize policy");
    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Top Secret"),
    ];

    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &policy_attributes,
        Some(meta_data),
    )
    .expect("cannot encrypt header")
}

#[cfg(feature = "interfaces")]
fn bench_header_encryption(c: &mut Criterion) {
    use abe_policy::AccessPolicy;

    let public_key_json: serde_json::Value = serde_json::from_str(include_str!(
        "../src/interfaces/hybrid_crypto/tests/public_master_key.json"
    ))
    .expect("cannot deserialize public key JSON");
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = key_value[0]["value"]
        .as_str()
        .expect("no key as hex found in JSON");
    let public_key =
        PublicKey::try_from_bytes(&hex::decode(hex_key).expect("cannot hex decode public key"))
            .expect("cannot deserialize public key");

    // Policy
    let policy_hex = key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .expect("no policy as hex found in JSON");
    let policy: Policy =
        serde_json::from_slice(&hex::decode(policy_hex).expect("cannot hex decode policy"))
            .expect("cannot deserialize policy");

    let mut group = c.benchmark_group("Header encryption");
    for i in 1..=5 {
        let access_policy = match i {
            1 => "Department::FIN ",
            2 => "Department::FIN && Security Level::Top Secret",
            3 => "Department::FIN && (Security Level::Top Secret || Security Level::High Secret)",
            4 => {
                "Department::FIN && (Security Level::Top Secret || Security Level::High Secret || \
                 Security Level::Medium Secret)"
            }
            5 => {
                "Department::FIN && (Security Level::Top Secret || Security Level::High Secret || \
                 Security Level::Medium Secret || Security Level::Low Secret)"
            }
            _ => "",
        };
        let access_policy = AccessPolicy::from_boolean_expression(access_policy).unwrap();
        let policy_attributes = access_policy.attributes();
        println!("{policy_attributes:?}");
        assert_eq!(i, policy_attributes.len());

        group.bench_function(format!("{i} partition"), |b| {
            b.iter(|| {
                encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
                    &policy,
                    &public_key,
                    &policy_attributes,
                    None,
                )
                .unwrap_or_else(|_| panic!("cannot encrypt header {}", i))
            })
        });
    }
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_encryption(c: &mut Criterion) {
    let public_key_json: serde_json::Value = serde_json::from_str(include_str!(
        "../src/interfaces/hybrid_crypto/tests/public_master_key.json"
    ))
    .expect("cannot deserialize public key JSON");
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = &key_value[0]["value"]
        .as_str()
        .expect("no key as hex found in JSON");
    let public_key =
        PublicKey::try_from_bytes(&hex::decode(hex_key).expect("cannot hex decode public key"))
            .expect("cannot deserialize public key");

    // Policy
    let policy_hex = key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .expect("no policy as hex found in JSON");
    let policy: Policy =
        serde_json::from_slice(&hex::decode(policy_hex).expect("cannot hex decode policy"))
            .expect("cannot deserialize policy");

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Top Secret"),
    ];
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let mut symmetric_key =
        vec![0u8; <<Aes256GcmCrypto as SymmetricCrypto>::Key as KeyTrait>::Length::to_usize()];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr().cast::<i8>();
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let policy_cs = CString::new(
        serde_json::to_string(&policy)
            .expect("cannot convert policy to string")
            .as_str(),
    )
    .expect("cannot create CString from String converted policy");

    let public_key_bytes = public_key
        .try_into_bytes()
        .expect("cannot get bytes from public key");

    let attributes_json = CString::new(
        serde_json::to_string(&policy_attributes)
            .expect("cannot convert policy attributes to string")
            .as_str(),
    )
    .expect("cannot create CString from String converted policy attributes");

    c.bench_function("FFI AES header encryption", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_encrypt_header(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                header_bytes_ptr,
                &mut header_bytes_len,
                policy_cs.as_ptr(),
                public_key_bytes.as_ptr().cast::<i8>(),
                public_key_bytes.len() as i32,
                attributes_json.as_ptr(),
                meta_data.uid.as_ptr().cast::<i8>(),
                meta_data.uid.len() as i32,
                meta_data
                    .additional_data
                    .as_ref()
                    .unwrap()
                    .as_ptr()
                    .cast::<i8>(),
                meta_data.additional_data.as_ref().unwrap().len() as i32,
            ))
            .expect("Failed unwrapping aes encrypt header FFI operation")
        })
    });
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_encryption_using_cache(c: &mut Criterion) {
    let public_key_json: serde_json::Value = serde_json::from_str(include_str!(
        "../src/interfaces/hybrid_crypto/tests/public_master_key.json"
    ))
    .expect("cannot deserialize public key JSON");
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let public_key =
        PublicKey::try_from_bytes(&hex::decode(hex_key).expect("cannot hex decode public key"))
            .expect("cannot deserialize public key");

    // Policy
    let policy_hex = key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .expect("no policy as hex found in JSON");
    let policy: Policy =
        serde_json::from_slice(&hex::decode(policy_hex).expect("cannot hex decode policy"))
            .expect("cannot deserialize policy");

    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Top Secret"),
    ];
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };

    let policy_cs = CString::new(
        serde_json::to_string(&policy)
            .expect("cannot convert policy to string")
            .as_str(),
    )
    .expect("cannot create CString from String converted policy");

    let public_key_bytes = public_key
        .try_into_bytes()
        .expect("cannot get bytes from public key");

    let mut cache_handle: i32 = 0;
    unsafe {
        unwrap_ffi_error(h_aes_create_encryption_cache(
            &mut cache_handle,
            policy_cs.as_ptr(),
            public_key_bytes.as_ptr().cast::<i8>(),
            public_key_bytes.len() as i32,
        ))
        .expect("cannot create aes encryption cache");
    }

    let mut symmetric_key =
        vec![0u8; <<Aes256GcmCrypto as SymmetricCrypto>::Key as KeyTrait>::Length::to_usize()];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut header_bytes_key = vec![0u8; 4096];
    let header_bytes_ptr = header_bytes_key.as_mut_ptr().cast::<i8>();
    let mut header_bytes_len = header_bytes_key.len() as c_int;

    let attributes_json = CString::new(
        serde_json::to_string(&policy_attributes)
            .expect("cannot convert policy attributes to string")
            .as_str(),
    )
    .expect("cannot create CString from String converted policy attributes");

    c.bench_function("FFI AES header encryption using cache", |b| {
        b.iter(|| unsafe {
            unwrap_ffi_error(h_aes_encrypt_header_using_cache(
                symmetric_key_ptr,
                &mut symmetric_key_len,
                header_bytes_ptr,
                &mut header_bytes_len,
                cache_handle,
                attributes_json.as_ptr(),
                meta_data.uid.as_ptr().cast::<i8>(),
                meta_data.uid.len() as i32,
                meta_data
                    .additional_data
                    .as_ref()
                    .unwrap()
                    .as_ptr()
                    .cast::<i8>(),
                meta_data.additional_data.as_ref().unwrap().len() as i32,
            ))
            .expect("Failed unwrapping FFI AES encrypt header operation")
        })
    });

    unsafe {
        unwrap_ffi_error(h_aes_destroy_encryption_cache(cache_handle))
            .expect("cannot destroy encryption cache");
    }
}

#[cfg(feature = "interfaces")]
fn bench_header_decryption(c: &mut Criterion) {
    use abe_policy::AccessPolicy;

    let public_key_json: serde_json::Value = serde_json::from_str(include_str!(
        "../src/interfaces/hybrid_crypto/tests/public_master_key.json"
    ))
    .expect("cannot deserialize public key JSON");
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = key_value[0]["value"]
        .as_str()
        .expect("no key as hex found in JSON");
    let public_key =
        PublicKey::try_from_bytes(&hex::decode(hex_key).expect("cannot hex decode public key"))
            .expect("cannot deserialize public key");

    // Policy
    let policy_hex = key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .expect("no policy as hex found in JSON");
    let policy: Policy =
        serde_json::from_slice(&hex::decode(policy_hex).expect("cannot hex decode policy"))
            .expect("cannot deserialize policy");

    let user_decryption_key_json: serde_json::Value = serde_json::from_str(include_str!(
        "../src/interfaces/hybrid_crypto/tests/fin_top_secret_user_key.json"
    ))
    .expect("cannot deserialize user key JSON");
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"]
        .as_str()
        .expect("no key as hex found in JSON");
    let user_decryption_key =
        UserDecryptionKey::try_from_bytes(&hex::decode(hex_key).expect("cannot hex decode key"))
            .expect("cannot generate user private key");

    for i in 2..=5 {
        let access_policy = match i {
            //1 => "Security Level::Top Secret",
            2 => "Department::FIN && Security Level::Top Secret",
            3 => "Department::FIN && (Security Level::Top Secret || Security Level::High Secret)",
            4 => {
                "Department::FIN && (Security Level::Top Secret || Security Level::High Secret || \
                 Security Level::Medium Secret)"
            }
            5 => {
                "Department::FIN && (Security Level::Top Secret || Security Level::High Secret || \
                 Security Level::Medium Secret || Security Level::Low Secret)"
            }
            _ => "",
        };
        let access_policy = AccessPolicy::from_boolean_expression(access_policy).unwrap();
        let policy_attributes = access_policy.attributes();
        println!("{policy_attributes:?}");
        assert_eq!(i, policy_attributes.len());

        let encrypted_header = encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
            &policy,
            &public_key,
            &policy_attributes,
            None,
        )
        .unwrap_or_else(|_| panic!("cannot encrypt header {}", i));
        c.bench_function(&format!("Header decryption/{i} partition(s)"), |b| {
            b.iter(|| {
                decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
                    &user_decryption_key,
                    &encrypted_header.encrypted_header_bytes,
                )
                .unwrap_or_else(|_| panic!("cannot decrypt hybrid header for {} partitions", i))
            })
        });
    }
}

#[cfg(feature = "ffi")]
fn bench_ffi_header_decryption(c: &mut Criterion) {
    let encrypted_header = generate_encrypted_header();

    let user_decryption_key_json: serde_json::Value = serde_json::from_str(include_str!(
        "../src/interfaces/hybrid_crypto/tests/fin_top_secret_user_key.json"
    ))
    .expect("cannot deserialize user key JSON");
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"]
        .as_str()
        .expect("no key as hex found in JSON");
    let user_decryption_key =
        UserDecryptionKey::try_from_bytes(&hex::decode(hex_key).expect("cannot hex decode key"))
            .expect("cannot generate user private key");

    let mut symmetric_key =
        vec![0u8; <<Aes256GcmCrypto as SymmetricCrypto>::Key as KeyTrait>::Length::to_usize()];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr().cast::<i8>();
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key
        .try_into_bytes()
        .expect("cannot get bytes from user decryption key");
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    c.bench_function("FFI AES header decryption", |b| {
        b.iter(|| unsafe {
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
            ))
            .expect("Failed unwrapping FFI AES decrypt header operation")
        })
    });
}

///
/// # Safety
#[cfg(feature = "ffi")]
fn bench_ffi_header_decryption_using_cache(c: &mut Criterion) {
    let encrypted_header = generate_encrypted_header();

    let user_decryption_key_json: serde_json::Value = serde_json::from_str(include_str!(
        "../src/interfaces/hybrid_crypto/tests/fin_top_secret_user_key.json"
    ))
    .expect("cannot deserialize user key JSON");
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"]
        .as_str()
        .expect("no key as hex found in JSON");
    let user_decryption_key =
        UserDecryptionKey::try_from_bytes(&hex::decode(hex_key).expect("cannot hex decode key"))
            .expect("cannot generate user private key");

    let mut symmetric_key =
        vec![0u8; <<Aes256GcmCrypto as SymmetricCrypto>::Key as KeyTrait>::Length::to_usize()];
    let symmetric_key_ptr = symmetric_key.as_mut_ptr().cast::<i8>();
    let mut symmetric_key_len = symmetric_key.len() as c_int;

    let mut uid = vec![0u8; 4096];
    let uid_ptr = uid.as_mut_ptr().cast::<i8>();
    let mut uid_len = uid.len() as c_int;

    let mut additional_data = vec![0u8; 4096];
    let additional_data_ptr = additional_data.as_mut_ptr().cast::<i8>();
    let mut additional_data_len = additional_data.len() as c_int;

    let user_decryption_key_bytes = user_decryption_key
        .try_into_bytes()
        .expect("cannot get bytes from user decryption key");
    let user_decryption_key_ptr = user_decryption_key_bytes.as_ptr().cast::<i8>();
    let user_decryption_key_len = user_decryption_key_bytes.len() as i32;

    let mut cache_handle: i32 = 0;
    unsafe {
        unwrap_ffi_error(h_aes_create_decryption_cache(
            &mut cache_handle,
            user_decryption_key_ptr,
            user_decryption_key_len,
        ))
        .expect("cannot create aes encryption cache");
    }

    c.bench_function("FFI AES header decryption using cache", |b| {
        b.iter(|| unsafe {
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
            ))
            .expect("Failed unwrapping FFI AES encrypt header operation")
        })
    });

    unsafe {
        unwrap_ffi_error(h_aes_destroy_decryption_cache(cache_handle))
            .expect("cannot destroy encryption cache");
    }
}

#[cfg(feature = "ffi")]
unsafe fn unwrap_ffi_error(val: i32) -> Result<(), FormatErr> {
    if val != 0 {
        let mut message_bytes_key = vec![0u8; 4096];
        let message_bytes_ptr = message_bytes_key.as_mut_ptr().cast::<i8>();
        let mut message_bytes_len = message_bytes_key.len() as c_int;
        get_last_error(message_bytes_ptr, &mut message_bytes_len);
        let cstr = CStr::from_ptr(message_bytes_ptr);
        Err(FormatErr::CryptoError(format!("ERROR: {}", cstr.to_str()?)))
    } else {
        Ok(())
    }
}

fn create_policies() -> (Vec<Node>, Vec<Vec<u32>>) {
    let attr_a = Box::new(Leaf(10));
    let _attr_b = Box::new(Leaf(11));
    let _attr_c = Box::new(Leaf(12));
    let _attr_d = Box::new(Leaf(13));

    let attr_1 = Box::new(Leaf(1));
    let attr_2 = Box::new(Leaf(2));
    let attr_3 = Box::new(Leaf(3));
    let attr_4 = Box::new(Leaf(4));
    let attr_5 = Box::new(Leaf(5));

    let msp_vec = vec![
        And(attr_1.clone(), attr_a.clone()),
        And(attr_a.clone(), Box::new(Or(attr_1.clone(), attr_2.clone()))),
        And(
            attr_a.clone(),
            Box::new(Or(
                attr_1.clone(),
                Box::new(Or(attr_2.clone(), attr_3.clone())),
            )),
        ),
        And(
            attr_a.clone(),
            Box::new(Or(
                Box::new(Or(attr_1.clone(), attr_2.clone())),
                Box::new(Or(attr_3.clone(), attr_4.clone())),
            )),
        ),
        And(
            attr_a,
            Box::new(Or(
                attr_1,
                Box::new(Or(
                    Box::new(Or(attr_2, attr_3)),
                    Box::new(Or(attr_4, attr_5)),
                )),
            )),
        ),
    ];

    let attr_vec = vec![
        vec![1, 10],
        vec![1, 10, 11],
        vec![1, 10, 11, 12],
        vec![1, 10, 11, 12, 13],
        vec![1, 10, 11, 12, 13, 14],
    ];

    (msp_vec, attr_vec)
}

fn bench_paper_policies(c: &mut Criterion) {
    let abe = Gpsw::<Bls12_381>::default();
    let msk = abe.generate_master_key(15).unwrap();
    let msg = abe.msg_encode(b"test").unwrap();

    let (user_attr, encapsulation_attr) = create_policies();
    for (i, attributes) in user_attr.into_iter().enumerate() {
        let msp = attributes.to_msp().unwrap();
        let usk = abe.key_generation(&msp, &msk.priv_key).unwrap();
        #[cfg(feature = "interfaces")]
        println!(
            "Serialized USK size ({} attriutes): {}",
            i + 1,
            usk.try_into_bytes().unwrap().len()
        );
        for (j, policy) in encapsulation_attr.iter().enumerate() {
            let enc = abe.encrypt(&msg, policy, &msk.pub_key).unwrap();
            #[cfg(feature = "interfaces")]
            if i == 0 {
                println!(
                    "Serialized encapsulation size ({} attriutes): {}",
                    j + 1,
                    enc.try_into_bytes().unwrap().len()
                );
            }
            c.bench_function(
                &format!(
                    "Encryption: user with {} partitions, encapsulation with {} partition(s)",
                    i + 1,
                    j + 1
                ),
                |b| {
                    b.iter(|| {
                        let _enc = abe.encrypt(&msg, policy, &msk.pub_key).unwrap();
                    })
                },
            );

            assert_eq!(
                msg,
                abe.decrypt(&enc, &usk).unwrap().expect("decrypt failed")
            );

            c.bench_function(
                &format!(
                    "Decryption: user with {} partitions, encapsulation with {} partition(s)",
                    i + 1,
                    j + 1
                ),
                |b| {
                    b.iter(|| {
                        let _dec = abe.decrypt(&enc, &usk).expect("decrypt failed");
                    })
                },
            );
        }
    }
}

criterion_group!(
    name = paper;
    config = Criterion::default().sample_size(5000);
    targets =
        bench_paper_policies,
);

#[cfg(feature = "interfaces")]
criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets =
        bench_header_encryption,
        bench_header_decryption
);

#[cfg(feature = "ffi")]
criterion_group!(
    name = benches_ffi;
    config = Criterion::default().sample_size(5000);
    targets =
        bench_ffi_header_encryption,
        bench_ffi_header_encryption_using_cache,
        bench_ffi_header_decryption,
        bench_ffi_header_decryption_using_cache
);

#[cfg(all(feature = "interfaces", feature = "ffi"))]
criterion_main!(benches, benches_ffi, paper);

#[cfg(all(feature = "interfaces", not(feature = "ffi")))]
criterion_main!(benches);

#[cfg(all(feature = "ffi", not(feature = "interfaces")))]
criterion_main!(benches_ffi);

/// if no feature enabled, can't run benchmark, but we
/// need placeholder for compilation to succeed
#[cfg(all(not(feature = "ffi"), not(feature = "interfaces")))]
fn main() {}
