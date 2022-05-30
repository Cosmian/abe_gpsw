use crate::core::gpsw::AsBytes;
use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        engine::Engine,
        gpsw::Gpsw,
        policy::{AccessPolicy, Attributes, Policy},
    },
    error::FormatErr,
};
use std::convert::TryFrom;

/// # Encryption using an Authorization Policy
/// This test demonstrates how data can be encrypted with policy attributes.
/// An user will only be able to decrypt data when it holds a key with the
/// proper attributes. This test also demonstrates revocation of an
/// attribute value and how to implement forward secrecy.
#[test]
fn abe() -> Result<(), FormatErr> {
    // ## Policy
    // In this demo, we will create a Policy which combines two axes, a
    // 'security level' and a 'department'. A user will be able to decrypt
    // data only if it possesses a key with a sufficient security level
    // and the code for the department.
    //
    // The parameter fixes the maximum number of revocations of attributes (see
    // below) for this Policy. This number influences the number of
    // public keys which will be ultimately generated for this Policy
    // and must be kept to a "reasonable" level to reduce security risks associated
    // with multiplying the number of keys.
    //
    // ## Policy Axes
    // The Policy is defined by two Policy Axes, thus defining a 2 dimensional
    // matrix of authorizations. An user must possess keys with attributes
    // from these two axes to be able to decrypt files.
    //
    // ### Security Level Axis
    // The first Policy Axis is the 'Security Level' axis and is a
    // hierarchical axis made of 5 levels: Protected, Low Secret , ...,
    // Top Secret. It is hierarchical: a user being granted access to level `n`
    // is automatically granted access to all levels below `n`. The attributes must
    // be provided in ascending order.
    //
    // ### Department Security Axis
    // The second Policy Axis is the Department axis and is made of 4 values: R&D,
    // HR, MKG, FIN. This axis is not hierarchical: granting access to an
    // attribute of this axis to a user does not give access to any other
    // attribute. Each attribute must be granted individually.
    let mut policy = Policy::new(100)
        .add_axis(
            "Security Level",
            &[
                "Protected",
                "Low Secret",
                "Medium Secret",
                "High Secret",
                "Top Secret",
            ],
            true,
        )?
        .add_axis("Department", &["R&D", "HR", "MKG", "FIN"], false)?;
    println!("policy: {:?}", hex::encode(&serde_json::to_vec(&policy)?));

    // ## Master Authority
    // The Master Authority possesses the keys for the given Policy:
    // a Secret Key which is used to delegate authority to "delegate authorities" -
    // which in turn generate user keys - and a Public key which is
    // used to encrypt data with the proper attributes.
    let engine = Engine::<Gpsw<Bls12_381>>::new();
    println!("Instantiating the ABE Master Keys (only once)...");
    let (master_private_key, public_key, delegation_key) = engine.generate_master_key(&policy)?;
    println!("public_key: {:?}", hex::encode(public_key.as_bytes()?));
    println!(
        "master_private_key: {:?}",
        hex::encode(master_private_key.as_bytes()?)
    );
    println!("... done. Running demo");

    // ## Delegate Authorities
    // The Master Authority will delegate part or all of its authority to "Delegate
    // Authorities" (a.k.a Delegates) which are the ones generating
    // user decryption keys.
    // In this particular example, the Master Authority will delegate its authority
    // to 2 Delegates:
    //  - a "High Secret Marketing and Finance Delegate" which can only generate
    //    User Keys for marketing (MKG) and/or finance (FIN) data of Security Level
    //    High Secret and below
    let high_secret_fin_mkg_access_policy = AccessPolicy::from_boolean_expression(
        "Security Level::High Secret && (Department::MKG || Department::FIN)",
    )?;
    let high_secret_mkg_fin_delegate = engine.generate_user_key(
        &policy,
        &master_private_key,
        &high_secret_fin_mkg_access_policy,
    )?;

    let top_secret_mkg_fin_delegate = engine.generate_user_key(
        &policy,
        &master_private_key,
        &AccessPolicy::from_boolean_expression(
            "Security Level::Top Secret && (Department::MKG || Department::FIN)",
        )?,
    )?;
    println!(
        "top_secret_mkg_fin_delegate: {:?}",
        hex::encode(top_secret_mkg_fin_delegate.as_bytes()?)
    );

    //
    //  - a Super Delegate which can issue User Keys for all Security Levels and all
    //    Departments. The special Access Policy `All` does not carry attributes and
    //    is therefore not subject to attributes revocation (see revocation below)
    let super_delegate =
        engine.generate_user_key(&policy, &master_private_key, &AccessPolicy::All)?;

    // ## User Keys
    // Delegate Authorities can now generate User Keys up to the level allowed by
    // their policy. A marketing user with Medium Secret security can have
    // its key generated by any of the Delegates.
    let medium_secret_mkg_access_policy =
        AccessPolicy::from_boolean_expression("Security Level::Medium Secret && Department::MKG")?;

    let _medium_secret_mkg_user = engine.delegate_user_key(
        &policy,
        &delegation_key,
        &super_delegate,
        &medium_secret_mkg_access_policy,
    )?;
    let medium_secret_mkg_user = engine.delegate_user_key(
        &policy,
        &delegation_key,
        &high_secret_mkg_fin_delegate,
        &medium_secret_mkg_access_policy,
    )?;
    println!(
        "medium_secret_mkg_user: {:?}",
        hex::encode(medium_secret_mkg_user.as_bytes()?)
    );

    // However, a Delegate cannot generate user keys for which it does not have the
    // authority
    let top_secret_mkg_access_policy =
        AccessPolicy::from_boolean_expression("Security Level::Top Secret && Department::MKG")?;
    let top_secret_user = engine.delegate_user_key(
        &policy,
        &delegation_key,
        &high_secret_mkg_fin_delegate,
        &top_secret_mkg_access_policy,
    );
    // FAILURE: as expected the High Secret marketing authority cannot generate user
    // keys for the Top Secret Security Level
    assert!(top_secret_user.is_err());

    let medium_secret_hr_access_policy =
        AccessPolicy::from_boolean_expression("Security Level::Medium Secret &&Department::HR")?;
    let hr_user = engine.delegate_user_key(
        &policy,
        &delegation_key,
        &high_secret_mkg_fin_delegate,
        &medium_secret_hr_access_policy,
    );
    // FAILURE: as expected the High Secret marketing authority cannot generate user
    // keys for Department HR
    assert!(hr_user.is_err());

    // Let us create a super user as well, which can decrypt everything
    // Note: the super_user, having `AccessPolicy::All` holds a randomization of the
    // super_delegate key
    let super_user = engine.delegate_user_key(
        &policy,
        &delegation_key,
        &super_delegate,
        &AccessPolicy::All,
    )?;

    // ## Encryption and Decryption
    // Data is encrypted using the Master Authority Public Key with two attributes:
    // one for the Security Level and one for the Department.
    //
    // Anyone who has access to the Public Key, can encrypt data with any
    // attribute combination. However, only users possessing user keys with
    // the right access policy can decrypt data.

    // ### A Low Secret marketing message
    // Let us create an encrypted marketing message with a Low Secret level
    let low_secret_mkg_message = engine.random_message()?;
    let low_secret_mkg_cipher_text = engine.encrypt(
        &policy,
        &public_key,
        Attributes::try_from("Security Level::Low Secret, Department::MKG")?.attributes(),
        &low_secret_mkg_message,
    )?;

    // Both users are able to decrypt the message
    let result = engine
        .decrypt(&low_secret_mkg_cipher_text, &medium_secret_mkg_user)?
        .expect("Decryption must works");
    assert_eq!(
        low_secret_mkg_message, result,
        "medium_secret_mkg_user_low_secret_mkg_message"
    );
    let result = engine
        .decrypt(&low_secret_mkg_cipher_text, &super_user)?
        .expect("Decryption must works");
    assert_eq!(
        low_secret_mkg_message, result,
        "super_user_low_secret_mkg_message"
    );

    // ### A Top Secret marketing message
    // However in the case of a Top Secret marketing message, only the super user
    // will succeed decrypting:
    let top_secret_mkg_message = engine.random_message()?;
    let top_secret_mkg_cipher_text = engine.encrypt(
        &policy,
        &public_key,
        Attributes::try_from("Security Level::Top Secret, Department::MKG")?.attributes(),
        &top_secret_mkg_message,
    )?;
    let result = engine.decrypt(&top_secret_mkg_cipher_text, &medium_secret_mkg_user)?;
    assert!(
        result.is_none(),
        "medium_secret_mkg_user_top_secret_mkg_message"
    );
    let result = engine
        .decrypt(&top_secret_mkg_cipher_text, &super_user)?
        .expect("Decryption must works");
    assert_eq!(
        top_secret_mkg_message, result,
        "super_user_top_secret_mkg_message"
    );

    // ### A Low Secret HR message
    // Likewise, in the case of a Low Secret HR message, only the super
    // user will succeed decrypting:
    let low_secret_hr_message = engine.random_message()?;
    let low_secret_hr_cipher_text = engine.encrypt(
        &policy,
        &public_key,
        Attributes::try_from("Security Level::Low Secret, Department::HR")?.attributes(),
        &low_secret_hr_message,
    )?;
    let result = engine.decrypt(&low_secret_hr_cipher_text, &medium_secret_mkg_user)?;
    assert!(
        result.is_none(),
        "medium_secret_mkg_user_low_secret_hr_message"
    );
    let result = engine
        .decrypt(&low_secret_hr_cipher_text, &super_user)?
        .expect("Decryption must works");
    assert_eq!(
        low_secret_hr_message, result,
        "super_user_low_secret_hr_message"
    );

    // ## Rotation of Policy attributes
    // At anytime, Policy attributes can be rotated.
    // When that happens future encryption of data for a "rotated" attribute cannot
    // be decrypted with user decryption keys which are not "refreshed" for that
    // attribute. Let us rotate the Security Level Low Secret
    policy.rotate(&("Security Level", "Low Secret").into())?;

    // We now encrypt a new marketing message at (the new) Low Secret level
    let new_low_level_mkg_message = engine.random_message()?;
    let new_low_level_mkg_cipher_text = engine.encrypt(
        &policy,
        &public_key,
        Attributes::try_from("Security Level::Low Secret, Department::MKG")?.attributes(),
        &new_low_level_mkg_message,
    )?;

    // The MKG user cannot decrypt the new message until its key is refreshed
    let result = engine.decrypt(&new_low_level_mkg_cipher_text, &medium_secret_mkg_user)?;
    assert!(
        result.is_none(),
        "old_medium_secret_mkg_user_new_low_secret_mkg_message"
    );

    // The super user can still decrypt, because its key was generated
    // with the special AccessPolicy `All`
    let result = engine
        .decrypt(&new_low_level_mkg_cipher_text, &super_user)?
        .expect("Decryption must works");
    assert_eq!(
        new_low_level_mkg_message, result,
        "super_user_new_low_secret_mkg_message"
    );

    // Except for the super delegate and super user key, all other keys need to be
    // refresh: Delegates and Users Delegate
    let high_secret_mkg_fin_delegate = engine.generate_user_key(
        &policy,
        &master_private_key,
        &high_secret_fin_mkg_access_policy,
    )?;
    // User
    let medium_secret_mkg_user = engine.delegate_user_key(
        &policy,
        &delegation_key,
        &high_secret_mkg_fin_delegate,
        &medium_secret_mkg_access_policy,
    )?;

    // New messages can now be decrypted
    let result = engine
        .decrypt(&new_low_level_mkg_cipher_text, &medium_secret_mkg_user)?
        .expect("Decryption must works");
    assert_eq!(new_low_level_mkg_message, result, "medium_secret_mkg_user");

    // Older messages can still be decrypted with the refreshed key as well
    let result = engine
        .decrypt(&low_secret_mkg_cipher_text, &medium_secret_mkg_user)?
        .expect("Decryption must works");
    assert_eq!(low_secret_mkg_message, result, "new_medium_secret_mkg_user");
    Ok(())
}
