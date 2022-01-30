use crate::core::{
    bilinear_map::bls12_381::Bls12_381,
    gpsw::{AbeScheme, AsBytes, Gpsw},
    policy::{attr, Policy},
    Engine,
};

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

#[test]
pub fn symmetric_key_test() {
    //-> anyhow::Result<()> {
    let public_key_str = include_str!("master_public_key.txt");
    let public_key = PublicKey::from_bytes(&hex::decode(public_key_str).unwrap()).unwrap();

    let policy_str = include_str!("policy.txt");
    let policy: Policy = serde_json::from_slice(&hex::decode(policy_str).unwrap()).unwrap();

    let user_decryption_key_str = include_str!("user_decryption_key.txt");
    let user_decryption_key =
        UserDecryptionKey::from_bytes(&hex::decode(user_decryption_key_str).unwrap()).unwrap();

    let abe = Engine::<Gpsw<Bls12_381>>::new();

    println!("{:?}", &policy);
    let policy_attributes = vec![
        attr("Department", "FIN"),
        attr("Security Level", "ConfidentialZ"),
    ];
    let (symmetric_key, encrypted_symmetric_key) = abe
        .generate_symmetric_key(&policy, &public_key, &policy_attributes, 32)
        .unwrap();

    assert_eq!(32, symmetric_key.len());

    let symmetric_key_ = abe
        .decrypt_symmetric_key(&user_decryption_key, &encrypted_symmetric_key, 32)
        .unwrap();
    assert_eq!(&symmetric_key, &symmetric_key_);
}
