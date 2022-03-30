use super::wit_generation::{
    decrypt, delegate_user_decryption_key, encrypt, generate_master_key,
    generate_user_decryption_key, rotate_attributes, Attribute, Policy, PolicyAxis,
};
use crate::core::policy::ap;

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

    let ciphertext = encrypt(
        "plaintext".to_string(),
        mk.public_key,
        vec![
            Attribute {
                axis_name: "Departments".to_string(),
                attribute: "MKG".to_string(),
            },
            Attribute {
                axis_name: "Security Level".to_string(),
                attribute: "level 3".to_string(),
            },
        ],
        updated_policy,
        // mk.policy_serialized,
    )
    .unwrap();

    let cleartext = decrypt(super_delegate, ciphertext).unwrap();
    assert_eq!("plaintext".to_string(), cleartext);
}
