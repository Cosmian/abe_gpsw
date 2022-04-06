// Tests performances:
// Install:
// curl https://wasmtime.dev/install.sh -sSf | bash
// cargo install cargo-wasi
// Launch bench
// cargo wasi test --release --features wit -- --nocapture single_test

use std::time::Instant;

use super::wit_generation::{
    decrypt, delegate_user_decryption_key, encrypt, generate_master_key,
    generate_user_decryption_key, rotate_attributes, Attribute, Policy, PolicyAxis,
};
use crate::{
    core::policy::ap,
    interfaces::wasi::wit_generation::{
        create_encryption_cache, destroy_encryption_cache, encrypt_hybrid_block,
        encrypt_hybrid_header,
    },
};

#[test]
fn access_policy_test() {
    let a = ap("SL", "level1");
    let b = ap("Country", "France");
    let c = a & b;
    let d = serde_json::to_string(&c).unwrap();
    println!("d: {:?}", d);
}

#[test]
fn single_test() {
    let policy = Policy {
        primary_axis: super::wit_generation::PolicyAxis {
            name: "Departments".to_string(),
            attributes: vec![
                "R&D".to_string(),
                "HR".to_string(),
                "MKG".to_string(),
                "FIN".to_string(),
            ],
            hierarchical: false,
        },
        secondary_axis: PolicyAxis {
            name: "Security Level".to_string(),
            attributes: vec![
                "level 1".to_string(),
                "level 2".to_string(),
                "level 3".to_string(),
                "level 4".to_string(),
                "level 5".to_string(),
            ],
            hierarchical: true,
        },
    };

    let mk = generate_master_key(100, policy).unwrap();

    let super_delegate =
        generate_user_decryption_key(mk.private_key.clone(), None, mk.policy_serialized.clone())
            .unwrap();

    let level_4_mkg_fin_delegate = generate_user_decryption_key(
        mk.private_key,
        Some("Departments::MKG && Security Level::level 4".to_string()),
        mk.policy_serialized.clone(),
    )
    .unwrap();

    let _level_3_mkg_fin_delegate = delegate_user_decryption_key(
        mk.delegation_key.clone(),
        level_4_mkg_fin_delegate,
        mk.policy_serialized.clone(),
        Some("Departments::MKG && Security Level::level 3".to_string()),
    );

    let updated_policy = rotate_attributes(
        mk.policy_serialized.clone(),
        vec![Attribute {
            axis_name: "Departments".to_string(),
            attribute: "MKG".to_string(),
        }],
    )
    .unwrap();

    let uid = vec![0_u8; 32];

    let loops = 10;
    let before = Instant::now();
    let abe_attributes = vec![
        Attribute {
            axis_name: "Departments".to_string(),
            attribute: "MKG".to_string(),
        },
        Attribute {
            axis_name: "Security Level".to_string(),
            attribute: "level 3".to_string(),
        },
    ];

    let mut ciphertext = Vec::<u8>::new();
    for _i in 0..loops {
        ciphertext = encrypt(
            "plaintext".to_string(),
            mk.public_key.clone(),
            abe_attributes.clone(),
            updated_policy.clone(),
            // mk.policy_serialized,
            uid.clone(),
        )
        .unwrap();
    }
    let avg_time = before.elapsed().as_micros() / loops;
    println!("\navg time (no cache)\t: {} micro seconds", avg_time);

    let cleartext = decrypt(super_delegate, ciphertext).unwrap();
    assert_eq!("plaintext".to_string(), cleartext);

    let cache_handle = create_encryption_cache(mk.public_key, updated_policy).unwrap();
    let before = Instant::now();
    for _i in 0..loops {
        let header =
            encrypt_hybrid_header(abe_attributes.clone(), cache_handle, uid.clone()).unwrap();
        encrypt_hybrid_block(
            "plaintext".to_string(),
            header.symmetric_key,
            uid.clone(),
            0,
        )
        .unwrap();
    }

    let avg_time = before.elapsed().as_micros() / loops;
    println!("avg time (with cache)\t: {} micro seconds", avg_time);

    destroy_encryption_cache(cache_handle).unwrap();
}
