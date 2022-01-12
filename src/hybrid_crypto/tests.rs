use cosmian_crypto_base::{
    entropy::new_uid, hybrid_crypto::Block, symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
};

use crate::{
    bilinear_map::bls12_381::Bls12_381,
    error::FormatErr,
    gpsw::{abe::Gpsw, AsBytes},
    hybrid_crypto::{
        decrypt, encrypt, generate_symmetric_key_and_header, generate_user_decryption_key,
    },
    policy::{ap, attr, Policy},
    Engine,
};

type Bl = Block<Aes256GcmCrypto>;
const CLEAR_TEXT_SIZE: usize = Bl::MAX_CLEAR_TEXT_LENGTH;

#[test]
fn single_test() -> Result<(), FormatErr> {
    let policy = Policy::new(10)
        .add_axis("Departments", &["FR", "AU", "DE"], false)?
        .add_axis("Levels", &["Sec_level_1", "Sec_level_2"], true)?;

    let engine = Engine::<Gpsw<Bls12_381>>::new(&policy);

    let mk = engine.generate_master_key()?;
    let sk = mk.0.as_bytes()?;
    let pk = mk.1.as_bytes()?;

    let uid = new_uid();
    let access_policy =
        ap("Levels", "Sec_level_1") & (ap("Departments", "FR") | ap("Departments", "AU"));

    let attributes = vec![attr("Levels", "Sec_level_1"), attr("Departments", "FR")];
    let (symmetric_key, encrypted_header) =
        generate_symmetric_key_and_header(&uid, &pk, &attributes, &engine.pg)?;

    let encrypted = encrypt(&symmetric_key, &uid, &[0_u8; 32], 0)?;

    let uk = generate_user_decryption_key(&sk, &access_policy, &engine.pg)?;
    let user_decryption_key =
        hex::decode(uk).map_err(|e| FormatErr::Deserialization(e.to_string()))?;

    let decrypted = decrypt(&user_decryption_key, &encrypted_header[..], &encrypted.0, 0)?;
    assert_eq!(decrypted.len(), 32);
    assert_eq!(decrypted, vec![0; 32]);

    let resume_encrypted = encrypt(&symmetric_key, &uid, &[1_u8; 32], 1)?;
    let decrypted = decrypt(
        &user_decryption_key[..],
        &encrypted_header,
        &resume_encrypted.0,
        1,
    )?;
    assert_eq!(decrypted.len(), 32);
    assert_eq!(decrypted, vec![1; 32]);
    Ok(())
}

#[test]
fn abe_multiple_encrypt_single_decrypt() -> Result<(), FormatErr> {
    let policy = Policy::new(10)
        .add_axis("Departments", &["FR", "AU", "DE"], false)?
        .add_axis("Levels", &["Sec_level_1", "Sec_level_2"], true)?;

    let engine = Engine::<Gpsw<Bls12_381>>::new(&policy);

    let mk = engine.generate_master_key()?;
    let sk = mk.0.as_bytes()?;
    let pk = mk.1.as_bytes()?;

    let uid = new_uid();
    let access_policy =
        ap("Levels", "Sec_level_2") & (ap("Departments", "FR") | ap("Departments", "AU"));

    let attributes = vec![attr("Levels", "Sec_level_1"), attr("Departments", "FR")];
    let (symmetric_key, encrypted_header) =
        generate_symmetric_key_and_header(&uid, &pk, &attributes, &engine.pg)?;

    let mut plain_text = [0_u8; CLEAR_TEXT_SIZE].to_vec();
    plain_text.extend_from_slice(&[1_u8; CLEAR_TEXT_SIZE].to_vec()[..]);
    plain_text.extend_from_slice(&[2_u8; 32].to_vec()[..]);

    let large_encrypted = encrypt(&symmetric_key, &uid, &[0_u8; CLEAR_TEXT_SIZE], 0)?;
    let large_encrypted_2 = encrypt(
        &symmetric_key,
        &uid,
        &[1_u8; CLEAR_TEXT_SIZE],
        large_encrypted.1,
    )?;
    let large_encrypted_3 = encrypt(&symmetric_key, &uid, &[2_u8; 32], large_encrypted_2.1)?;

    let mut cipher_text = large_encrypted.0;
    cipher_text.extend_from_slice(&large_encrypted_2.0[..]);
    cipher_text.extend_from_slice(&large_encrypted_3.0[..]);

    let uk = generate_user_decryption_key(&sk, &access_policy, &engine.pg)?;
    let user_decryption_key =
        hex::decode(uk).map_err(|e| FormatErr::Deserialization(e.to_string()))?;

    let decrypted = decrypt(&user_decryption_key, &encrypted_header, &cipher_text, 0)?;

    assert_eq!(decrypted.len(), 2 * CLEAR_TEXT_SIZE + 32);
    assert_eq!(decrypted, plain_text);
    Ok(())
}

#[test]
fn key_generation() -> Result<(), FormatErr> {
    let policy = Policy::new(10)
        .add_axis("Departments", &["FR", "AU", "DE"], false)?
        .add_axis("Levels", &["Sec_level_1", "Sec_level_2"], true)?;

    let engine = Engine::<Gpsw<Bls12_381>>::new(&policy);

    let mk = engine.generate_master_key()?;
    let sk = mk.0.as_bytes()?;
    // let pk = mk.1.as_bytes()?;

    let access_policy =
        ap("Levels", "Sec_level_1") & (ap("Departments", "FR") | ap("Departments", "AU"));
    let uk = generate_user_decryption_key(&sk, &access_policy, &engine.pg)?;
    let uk2 = generate_user_decryption_key(&sk, &access_policy, &engine.pg)?;

    assert_ne!(uk, uk2);

    Ok(())
}
