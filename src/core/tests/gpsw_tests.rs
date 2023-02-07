use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{
            scheme::{
                GpswCipherText, GpswDecryptionKey, GpswMasterPrivateKey,
                GpswMasterPublicDelegationKey, GpswMasterPublicKey,
            },
            AsBytes, Gpsw,
        },
        msp::Node::{self, And, Leaf, Or},
    },
    error::FormatErr,
};

#[test]
fn encrypt_decrypt() -> Result<(), FormatErr> {
    let a = Box::new(Leaf(1));
    let b = Box::new(Leaf(2));
    let c = Box::new(Leaf(3));
    let d = Box::new(Leaf(4));
    let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
    println!("formula: {formula}");
    let msp = formula.to_msp()?;
    println!("msp: {msp}");

    let abe = Gpsw {
        group: Bls12_381::default(),
    };

    let mk = abe.generate_master_key(10)?;
    let uk = abe.key_generation(&msp, &mk.priv_key)?;
    let message = abe.msg_encode(b"test")?;
    let gamma = [1, 4];
    let enc = abe.encrypt(&message, &gamma, &mk.pub_key)?;

    println!("decrypt");
    let dec = abe.decrypt(&enc, &uk)?.expect("decrypt failed");
    println!("\nDecryption Ok: {}", message == dec);
    Ok(())
}

#[test]
fn user_key_as_bytes() -> Result<(), FormatErr> {
    let a = Box::new(Leaf(1));
    let b = Box::new(Leaf(2));
    let c = Box::new(Leaf(3));
    let d = Box::new(Leaf(4));
    let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
    println!("formula: {formula}");
    let msp = formula.to_msp()?;
    println!("msp: {msp}");

    let abe = Gpsw {
        group: Bls12_381::default(),
    };

    let mk = abe.generate_master_key(10)?;
    let uk = abe.key_generation(&msp, &mk.priv_key)?;
    let uk_2 = GpswDecryptionKey::<Bls12_381>::try_from_bytes(&uk.try_into_bytes()?)?;

    assert_eq!(uk.msp, uk_2.msp);
    assert_eq!(uk.raw_d_i, uk_2.raw_d_i);
    Ok(())
}

#[test]
fn ciphertext_as_bytes() -> Result<(), FormatErr> {
    let a = Box::new(Leaf(1));
    let b = Box::new(Leaf(2));
    let c = Box::new(Leaf(3));
    let d = Box::new(Leaf(4));
    let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
    println!("formula: {formula}");
    let msp = formula.to_msp()?;
    println!("msp: {msp}");

    let abe = Gpsw {
        group: Bls12_381::default(),
    };

    let mk = abe.generate_master_key(10)?;
    let message = abe.msg_encode(b"test")?;
    let gamma = [1, 4];
    let enc = abe.encrypt(&message, &gamma, &mk.pub_key)?;
    let enc_2 = GpswCipherText::<Bls12_381>::try_from_bytes(&enc.try_into_bytes()?)?;

    assert_eq!(enc.gamma, enc_2.gamma);
    assert_eq!(enc.e_prime, enc_2.e_prime);
    assert_eq!(enc.e_i, enc_2.e_i);
    Ok(())
}

#[test]
fn master_public_key_as_bytes() -> Result<(), FormatErr> {
    let a = Box::new(Leaf(1));
    let b = Box::new(Leaf(2));
    let c = Box::new(Leaf(3));
    let d = Box::new(Leaf(4));
    let formula = And(a, Box::new(Or(d, Box::new(And(b, c)))));
    println!("formula: {formula}");
    let msp = formula.to_msp()?;
    println!("msp: {msp}");

    let abe = Gpsw {
        group: Bls12_381::default(),
    };

    let mk = abe.generate_master_key(10)?;
    let mpk = mk.pub_key;
    let mpk_2 = GpswMasterPublicKey::<Bls12_381>::try_from_bytes(&mpk.try_into_bytes()?)?;

    assert_eq!(mpk.t_i, mpk_2.t_i);
    assert_eq!(mpk.y, mpk_2.y);
    Ok(())
}

#[test]
fn encrypt_decrypt_with_multiple_key_pair() -> Result<(), FormatErr> {
    let policy_1 = Node::parse("1 | 2")?.to_msp()?;
    let policy_2 = Node::parse("1 & 2")?.to_msp()?;
    let policy_3 = Node::parse("1")?.to_msp()?;
    let policy_4 = Node::parse("1 & 3")?.to_msp()?;
    let policy_5 = Node::parse("1 | 3")?.to_msp()?;

    let abe = Gpsw {
        group: Bls12_381::default(),
    };

    let mk = abe.generate_master_key(10)?;
    let uk = abe.key_generation(&policy_1, &mk.priv_key)?;
    let uk2 = abe.key_generation(&policy_2, &mk.priv_key)?;
    let uk3 = abe.key_generation(&policy_3, &mk.priv_key)?;
    let uk4 = abe.key_generation(&policy_4, &mk.priv_key)?;
    let uk5 = abe.key_generation(&policy_5, &mk.priv_key)?;

    println!("msp 1: {}", uk.msp);
    println!("msp 2: {}", uk2.msp);
    println!("msp 2: {}", uk3.msp);
    println!("msp 2: {}", uk4.msp);

    let msg = abe.msg_encode(b"test")?;

    let gamma = [1, 2];
    let enc = abe.encrypt(&msg, &gamma, &mk.pub_key)?;

    let dec = abe.decrypt(&enc, &uk)?.expect("decrypt failed");
    assert_eq!(msg, dec);
    println!("\nDecryption Ok: {}", msg == dec);

    let dec2 = abe.decrypt(&enc, &uk2)?.expect("decrypt failed");
    assert_eq!(msg, dec2);
    println!("\nDecryption Ok: {}", msg == dec2);

    let dec3 = abe.decrypt(&enc, &uk3)?.expect("decrypt failed");
    assert_eq!(msg, dec3);
    println!("\nDecryption Ok: {}", msg == dec3);

    let dec4 = abe.decrypt(&enc, &uk4)?;
    assert_eq!(dec4, None);

    let dec5 = abe.decrypt(&enc, &uk5)?.expect("decrypt failed");
    assert_eq!(msg, dec5);
    println!("\nDecryption Ok: {}", msg == dec5);

    Ok(())
}

#[test]
fn master_private_key_as_bytes() -> Result<(), FormatErr> {
    let abe = Gpsw {
        group: Bls12_381::default(),
    };
    let mk = abe.generate_master_key(10)?;
    let mpk = mk.priv_key;
    let mpk_2 = GpswMasterPrivateKey::<Bls12_381>::try_from_bytes(&mpk.try_into_bytes()?)?;

    assert_eq!(mpk.t_i, mpk_2.t_i);
    assert_eq!(mpk.y, mpk_2.y);
    Ok(())
}

#[test]
fn master_public_delegation_key_as_bytes() -> Result<(), FormatErr> {
    let abe = Gpsw {
        group: Bls12_381::default(),
    };
    let mk = abe.generate_master_key(10)?;
    let mpk = mk.del_key;
    let mpk_2 = GpswMasterPublicDelegationKey::<Bls12_381>::try_from_bytes(&mpk.try_into_bytes()?)?;

    assert_eq!(mpk.inv_t_i, mpk_2.inv_t_i);
    Ok(())
}
