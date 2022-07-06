use crate::core::{
    bilinear_map::bls12_381::Bls12_381,
    gpsw::{AbeScheme, AsBytes, Gpsw},
    msp::policy_to_msp,
    Engine,
};
use abe_policy::{AccessPolicy, Attribute, Policy, PolicyAxis};

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

#[test]
pub fn symmetric_key_test() {
    let public_key_str = include_str!("master_public_key.txt");
    let public_key = PublicKey::try_from_bytes(&hex::decode(public_key_str).unwrap()).unwrap();

    let policy_str = include_str!("policy.txt");
    let policy: Policy = serde_json::from_slice(&hex::decode(policy_str).unwrap()).unwrap();

    let user_decryption_key_str = include_str!("user_decryption_key.txt");
    let user_decryption_key =
        UserDecryptionKey::try_from_bytes(&hex::decode(user_decryption_key_str).unwrap()).unwrap();

    let abe = Engine::<Gpsw<Bls12_381>>::new();

    println!("{:?}", &policy);
    let policy_attributes = vec![
        Attribute::new("Department", "FIN"),
        Attribute::new("Security Level", "Confidential"),
    ];
    let (symmetric_key, encrypted_symmetric_key) = abe
        .generate_symmetric_key(&policy, &public_key, &policy_attributes, 32)
        .unwrap();

    assert_eq!(32, symmetric_key.len());

    let symmetric_key_ = abe
        .decrypt_symmetric_key(&user_decryption_key, &encrypted_symmetric_key, 32)
        .unwrap();
    assert_eq!(&symmetric_key, &symmetric_key_);

    // Regenerate test vector (if needed)
    let mk = abe.generate_master_key(&policy).unwrap();
    let public_key = mk.1;
    println!("public_key: {}", public_key);
    let access_policy =
        AccessPolicy::from_boolean_expression("Security Level::Confidential && Department::FIN")
            .unwrap();
    let user_decryption_key = abe
        .generate_user_key(&policy, &mk.0, &access_policy)
        .unwrap();
    println!("user_decryption_key: {user_decryption_key}");
    //
}

#[test]
pub fn complex_access_policy_test() {
    let mut policy = Policy::new(100);

    policy
        .add_axis(&PolicyAxis::new(
            "Entity",
            &["BCEF", "BNPPF", "CIB", "CashMgt"],
            false,
        ))
        .unwrap();

    policy
        .add_axis(&PolicyAxis::new(
            "Country",
            &["France", "Germany", "Italy", "Hungary", "Spain", "Belgium"],
            false,
        ))
        .unwrap();

    let engine = Engine::<Gpsw<Bls12_381>>::new();
    let (master_private_key, public_key, _delegation_key) =
        engine.generate_master_key(&policy).unwrap();

    let bnppf_all_access_policy = AccessPolicy::from_boolean_expression(
        "Entity::BNPPF && (Country::France || Country::Germany || Country::Italy || \
         Country::Hungary || Country::Spain || Country::Belgium)",
    )
    .unwrap();

    // Verify access policy (optional check)
    policy_to_msp(&policy, &bnppf_all_access_policy).unwrap();

    println!(
        "{}",
        serde_json::to_string(&bnppf_all_access_policy).unwrap()
    );

    let bnppf_all_user = engine
        .generate_user_key(&policy, &master_private_key, &bnppf_all_access_policy)
        .unwrap();

    let bnppf_france_message = engine.random_message().unwrap();

    // Check that wrong encryption-attributes give an error. This error is an
    // `FormatErr:AttributeNotFound`
    assert!(engine
        .encrypt(
            &policy,
            &public_key,
            &[("Bad_Entity", "BNPPF").into(), ("Country", "France").into()],
            &bnppf_france_message,
        )
        .is_err());

    let bnppf_france_cipher_text = engine
        .encrypt(
            &policy,
            &public_key,
            &[("Entity", "BNPPF").into(), ("Country", "France").into()],
            &bnppf_france_message,
        )
        .unwrap();

    // check it can decrypt
    let clear_text = engine
        .decrypt(&bnppf_france_cipher_text, &bnppf_all_user)
        .unwrap()
        .unwrap();
    assert_eq!(bnppf_france_message, clear_text);

    // recreate user key vie access policy serde

    let bnppf_all_access_policy_: AccessPolicy =
        serde_json::from_str(&serde_json::to_string(&bnppf_all_access_policy).unwrap()).unwrap();

    let bnppf_all_user_ = engine
        .generate_user_key(&policy, &master_private_key, &bnppf_all_access_policy_)
        .unwrap();

    let clear_text_ = engine
        .decrypt(&bnppf_france_cipher_text, &bnppf_all_user_)
        .unwrap()
        .unwrap();
    assert_eq!(bnppf_france_message, clear_text_);
}
