use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, AsBytes, Gpsw},
        policy::{attr, Policy},
    },
    interfaces::hybrid_crypto::{
        decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_block, encrypt_hybrid_header,
        symmetric_encryption_overhead,
    },
};
use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Key},
};
use serde_json::Value;

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

// maximum clear text size that can be safely encrypted with AES GCM (using a single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

#[test]
pub fn test_aes_hybrid_encryption() -> anyhow::Result<()> {
    let public_key_json: Value = serde_json::from_str(include_str!("./public_master_key.json"))?;
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let public_key = PublicKey::from_bytes(&hex::decode(hex_key)?)?;

    // Policy
    let policy_hex = &key_value[1]["value"][4]["value"][0]["value"][2]["value"]
        .as_str()
        .unwrap();
    let policy: Policy = serde_json::from_slice(&hex::decode(policy_hex)?)?;

    let policy_attributes = vec![
        attr("Department", "FIN"),
        attr("Security Level", "Confidential"),
    ];
    let meta_data = Metadata {
        uid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        additional_data: vec![10, 11, 12, 13, 14],
    };
    let encrypted_header = encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &policy_attributes,
        meta_data.clone(),
    )?;

    let symmetric_key = &encrypted_header.symmetric_key;
    let encrypted_header_bytes = &encrypted_header.encrypted_header_bytes;
    assert_eq!(32, symmetric_key.as_bytes().len());
    println!("Encrypted Header len {}", encrypted_header_bytes.len());

    let clear_text = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let encrypted_block = encrypt_hybrid_block::<
        Gpsw<Bls12_381>,
        Aes256GcmCrypto,
        MAX_CLEAR_TEXT_SIZE,
    >(symmetric_key, &meta_data.uid, 0, &clear_text)?;
    assert_eq!(
        clear_text.len() + symmetric_encryption_overhead::<Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(),
        encrypted_block.len()
    );

    let user_decryption_key_json: Value =
        serde_json::from_str(include_str!("./fin_confidential_user_key.json"))?;
    let key_value = &user_decryption_key_json["value"][0]["value"][1]["value"];
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let user_decryption_key = UserDecryptionKey::from_bytes(&hex::decode(hex_key)?)?;
    println!(
        "User decryption Key len {}",
        &user_decryption_key.as_bytes()?.len()
    );

    let header_ = decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &user_decryption_key,
        encrypted_header_bytes,
    )?;
    assert_eq!(&symmetric_key.as_bytes(), &header_.symmetric_key.as_bytes());
    assert_eq!(&meta_data, &header_.meta_data);

    let clear_text_ = decrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &header_.symmetric_key,
        &header_.meta_data.uid,
        0,
        &encrypted_block,
    )?;
    assert_eq!(&clear_text, &clear_text_);

    Ok(())
}
