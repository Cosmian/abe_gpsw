use std::convert::TryFrom;

use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, SymmetricCrypto},
    KeyTrait,
};
use serde_json::Value;

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, AsBytes, Gpsw},
        policy::{attr, Policy},
    },
    error::FormatErr,
    interfaces::hybrid_crypto::{
        decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_block, encrypt_hybrid_header,
        symmetric_encryption_overhead,
    },
};

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;

// maximum clear text size that can be safely encrypted with AES GCM (using a
// single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1 << 30;

#[test]
pub fn test_aes_hybrid_encryption() -> Result<(), FormatErr> {
    let public_key_json: Value = serde_json::from_str(include_str!("./public_master_key.json"))?;
    let key_value = &public_key_json["value"][0]["value"][1]["value"];

    // Public Key bytes
    let hex_key = &key_value[0]["value"].as_str().unwrap();
    let public_key = PublicKey::try_from_bytes(&hex::decode(hex_key)?)?;

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
        additional_data: Some(vec![10, 11, 12, 13, 14]),
    };
    let encrypted_header = encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &policy_attributes,
        Some(meta_data.clone()),
    )?;

    let symmetric_key = &encrypted_header.symmetric_key;
    let encrypted_header_bytes = &encrypted_header.encrypted_header_bytes;
    let symmetric_key_bytes: Vec<u8> = symmetric_key.into();
    assert_eq!(32, symmetric_key_bytes.len());
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
    let user_decryption_key = UserDecryptionKey::try_from_bytes(&hex::decode(hex_key)?)?;
    println!(
        "User decryption Key len {}",
        &user_decryption_key.try_into_bytes()?.len()
    );

    let header_ = decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &user_decryption_key,
        encrypted_header_bytes,
    )?;
    let symmetric_key_bytes: Vec<u8> = symmetric_key.to_bytes();
    let header_symmetric_key_bytes: Vec<u8> = header_.symmetric_key.to_bytes();
    assert_eq!(&symmetric_key_bytes, &header_symmetric_key_bytes);
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

#[test]
pub fn test_non_reg_decrypt_hybrid_block() -> Result<(), FormatErr> {
    let symmetric_key_hex = "802de96f19589fbc0eb2f26705dc1ed261e9c80f2fec301ca7d0ecea3176405b";
    let symmetric_key =
        <Aes256GcmCrypto as SymmetricCrypto>::Key::try_from(hex::decode(symmetric_key_hex)?)?;
    let uid_hex = "cd8ca2eeb654b5f39f347f4e3f91b3a15c450c1e52c40716237b4c18510f65b4";
    let encrypted_bytes = "e09ba17fdff90afbb18546211268b8aef6517a73b701283ab334c0720372f565c751a311c1ec09a6bbb070f8a1961ca3f048b280ea36a578a0068edea8408f3cf4ab26f5a71933dffed384ea7d33e42c16fe17a1026937a345386bb980917d6d2175a48b6d69e8322689dde0bf99cee9d2da5bbee1f29b2005725b6969021462e6608284a5135677b03d8fcce03563cc4d8988f455d27b95ef62080f4c2f18e7897636ac69e9d216668765d2025f66c805d549c4ef779c32ac3286bee8d35c1b758b51f1686d2aea996cc1f3bfff2aea7d605cce963e5bc69f77f284a1c05b803df08fcdec6a6d4f0c74ad8f6076d9ca692642dcdff64a34d1fbbb4d57aea776ce8032b03d63c9e376377fb95725b6d3ac6be3a29f47d15eb22b5c81bf6168785844da8d22914076415957d9e253142f14c5c68fbe1108d74832e2347425f89b46321ac0c7b939f793e3c39e5dbb83d9e6be29db4aa3df0e645cc859aac9a0324d546b70856e2ae89c77b87a8e25eac90f9265642bbd8c407f0aa307aef613bd79fa8fd6c959c959007791621e5fe047edfcadae2c195bb681b6621a9583c8d51911e39df50331b495b603fbf826eebeffe26cd2bc0287a280801bc54cfa9fed1279a58843bb8ea1262982753481dc61852cca49279d0de5e287f6a43dca38";

    let _clear_text = decrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
        &symmetric_key,
        &hex::decode(uid_hex)?,
        0,
        &hex::decode(encrypted_bytes)?,
    )?;

    Ok(())
}
