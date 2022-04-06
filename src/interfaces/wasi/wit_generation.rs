// Since wit_generation.rs code is called from the Cargo feature `wasi_impl`,
// rustc cannot see that code is actually not a dead code
#![allow(dead_code)]

use std::{
    collections::HashMap,
    convert::TryInto,
    sync::{
        atomic::{AtomicI32, Ordering},
        RwLock,
    },
};

use cosmian_crypto_base::{
    hybrid_crypto::Metadata,
    symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Key, SymmetricCrypto},
};
use lazy_static::lazy_static;
use witgen::witgen;

use crate::{
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{
            scheme::{GpswDecryptionKey, GpswMasterPublicKey},
            AbeScheme, AsBytes, Gpsw,
        },
        policy::{attr, AccessPolicy},
        Engine,
    },
    interfaces::hybrid_crypto::{
        decrypt_hybrid_block as internal_decrypt_hybrid_block,
        decrypt_hybrid_header as internal_decrypt_hybrid_header,
        encrypt_hybrid_block as internal_encrypt_hybrid_block,
        encrypt_hybrid_header as internal_encrypt_hybrid_header,
    },
};

type PublicKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey;
type PrivateKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPrivateKey;
type UserDecryptionKey = <Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey;
type DelegationKey = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicDelegationKey;

// maximum clear text size that can be safely encrypted with AES GCM (using a
// single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

#[witgen]
pub struct PolicyAxis {
    pub name: String,
    pub attributes: Vec<String>,
    pub hierarchical: bool,
}

/// This struct only provides a visual way to display policy arguments
#[witgen]
pub struct Policy {
    pub primary_axis: PolicyAxis,
    pub secondary_axis: PolicyAxis,
}

/// Regroup private, public and delegation keys in same struct
#[witgen]
pub struct MasterKey {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub delegation_key: Vec<u8>,
    pub policy_serialized: Vec<u8>,
}

/// This struct only provides a visual way to display attributes arguments
#[witgen]
#[derive(Clone)]
pub struct Attribute {
    pub axis_name: String,
    pub attribute: String,
}
impl Attribute {
    fn abe_attributes(attributes: &[Attribute]) -> Vec<crate::core::policy::Attribute> {
        attributes
            .iter()
            .map(|a| attr(&a.axis_name, &a.attribute))
            .collect::<Vec<_>>()
    }
}

fn policy_to_abe_policy(
    nb_revocation: usize,
    policy: &Policy,
) -> Result<crate::core::policy::Policy, String> {
    let x = policy
        .primary_axis
        .attributes
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<_>>();
    let y = policy
        .secondary_axis
        .attributes
        .iter()
        .map(|y| y.as_str())
        .collect::<Vec<_>>();
    let abe_policy = crate::core::policy::Policy::new(nb_revocation)
        .add_axis(
            &policy.primary_axis.name,
            &x,
            policy.primary_axis.hierarchical,
        )
        .map_err(|e| e.to_string())?
        .add_axis(
            &policy.secondary_axis.name,
            &y,
            policy.secondary_axis.hierarchical,
        )
        .map_err(|e| e.to_string())?;

    Ok(abe_policy)
}

#[witgen]
/// Generate ABE master key
pub fn generate_master_key(nb_revocation: usize, policy: Policy) -> Result<MasterKey, String> {
    let abe_policy = policy_to_abe_policy(nb_revocation, &policy)?;

    let engine = Engine::<Gpsw<Bls12_381>>::new();
    let mk = engine
        .generate_master_key(&abe_policy)
        .map_err(|e| e.to_string())?;

    // Only serialization from here
    let private_key = mk.0.as_bytes().map_err(|e| e.to_string())?;
    let public_key = mk.1.as_bytes().map_err(|e| e.to_string())?;
    let delegation_key = mk.2.as_bytes().map_err(|e| e.to_string())?;
    let policy_serialized = serde_json::to_vec(&abe_policy).map_err(|e| e.to_string())?;
    Ok(MasterKey {
        private_key,
        public_key,
        delegation_key,
        policy_serialized,
    })
}

#[witgen]
/// Generate a user decryption key for the given master key and access policy
pub fn generate_user_decryption_key(
    master_private_key: Vec<u8>,
    access_policy: Option<String>,
    policy: Vec<u8>,
) -> Result<String, String> {
    let policy = &serde_json::from_slice(&policy).map_err(|e| e.to_string())?;
    let access_policy = access_policy
        .map_or(Ok(AccessPolicy::All), |a| {
            AccessPolicy::from_boolean_expression(&a).map_err(|e| e.to_string())
        })
        .map_err(|e| e)?;
    let engine = Engine::<Gpsw<Bls12_381>>::new();
    let msk = PrivateKey::from_bytes(&master_private_key).map_err(|e| e.to_string())?;
    Ok(engine
        .generate_user_key(policy, &msk, &access_policy)
        .map_err(|e| e.to_string())?
        .to_string())
}

// -------------------------------
//         Encryption
// -------------------------------

#[witgen]
/// Encrypt an AES-symmetric key and encrypt with AESGCM-256
pub fn encrypt(
    plaintext: String,
    master_public_key: Vec<u8>,
    attributes: Vec<Attribute>,
    policy: Vec<u8>,
    uid: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let policy = serde_json::from_slice(&policy).map_err(|e| e.to_string())?;
    let abe_attributes = Attribute::abe_attributes(&attributes);
    let public_key = PublicKey::from_bytes(&master_public_key).map_err(|e| e.to_string())?;

    let encrypted_header = internal_encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &policy,
        &public_key,
        &abe_attributes,
        Metadata {
            uid: uid.clone(),
            additional_data: None,
        },
    )
    .map_err(|e| e.to_string())?;

    let encrypted_block =
        internal_encrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
            &encrypted_header.symmetric_key,
            &uid,
            0,
            plaintext.as_bytes(),
        )
        .map_err(|e| e.to_string())?;

    let header_len = u32::to_be_bytes(encrypted_header.encrypted_header_bytes.len() as u32);

    let mut result = header_len.to_vec();
    result.extend_from_slice(&encrypted_header.encrypted_header_bytes);
    result.extend_from_slice(&encrypted_block);
    Ok(result)
}

// A static cache of the Encryption Caches
lazy_static! {
    static ref ENCRYPTION_CACHE_MAP: RwLock<HashMap<i32, EncryptionCache>> =
        RwLock::new(HashMap::new());
    static ref NEXT_ENCRYPTION_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

/// An Encryption Cache that will be used to cache Rust side
/// the Public Key and the Policy when doing multiple serial encryptions
pub struct EncryptionCache {
    policy: crate::core::policy::Policy,
    public_key: GpswMasterPublicKey<Bls12_381>,
}

#[witgen]
/// Prepare encryption cache (avoiding public key deserialization)
pub fn create_encryption_cache(master_public_key: Vec<u8>, policy: Vec<u8>) -> Result<i32, String> {
    let policy: crate::core::policy::Policy =
        serde_json::from_slice(&policy).map_err(|e| e.to_string())?;
    let public_key = PublicKey::from_bytes(&master_public_key).map_err(|e| e.to_string())?;

    let cache = EncryptionCache { policy, public_key };
    let id = NEXT_ENCRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.insert(id, cache);
    Ok(id)
}

#[witgen]
pub fn destroy_encryption_cache(cache_handle: i32) -> Result<(), String> {
    let mut map = ENCRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on encryption cache failed");
    map.remove(&cache_handle);
    Ok(())
}

#[witgen]
pub struct EncryptedHeader {
    pub symmetric_key: Vec<u8>,
    pub encrypted_header_bytes: Vec<u8>,
}

#[witgen]
/// Encrypt an AES-symmetric key and encrypt with AESGCM-256
pub fn encrypt_hybrid_header(
    attributes: Vec<Attribute>,
    cache_handle: i32,
    uid: Vec<u8>,
) -> Result<EncryptedHeader, String> {
    let map = ENCRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the encryption cache failed");
    let cache = map.get(&cache_handle).expect("invalid cache handle");

    let encrypted_header = internal_encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &cache.policy,
        &cache.public_key,
        &Attribute::abe_attributes(&attributes),
        Metadata {
            uid,
            additional_data: None,
        },
    )
    .map_err(|e| e.to_string())?;

    Ok(EncryptedHeader {
        symmetric_key: encrypted_header.symmetric_key.as_bytes(),
        encrypted_header_bytes: encrypted_header.encrypted_header_bytes,
    })
}

#[witgen]
/// Encrypt an AES-symmetric key and encrypt with AESGCM-256
pub fn encrypt_hybrid_block(
    plaintext: String,
    symmetric_key: Vec<u8>,
    uid: Vec<u8>,
    block_number: u64,
) -> Result<Vec<u8>, String> {
    let symmetric_key = <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(symmetric_key)
        .map_err(|e| e.to_string())?;

    let encrypted_block =
        internal_encrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
            &symmetric_key,
            &uid,
            block_number as usize,
            plaintext.as_bytes(),
        )
        .map_err(|e| e.to_string())?;

    Ok(encrypted_block)
}

// -------------------------------
//         Decryption
// -------------------------------

// A cache of the encryption caches
lazy_static! {
    static ref DECRYPTION_CACHE_MAP: RwLock<HashMap<i32, DecryptionCache>> =
        RwLock::new(HashMap::new());
    static ref NEXT_DECRYPTION_CACHE_ID: std::sync::atomic::AtomicI32 = AtomicI32::new(0);
}

/// A Decryption Cache that will be used to cache Rust side
/// the User Decryption Key when performing serial decryptions
pub struct DecryptionCache {
    user_decryption_key: GpswDecryptionKey<Bls12_381>,
}

#[witgen]
/// Prepare encryption cache (avoiding user decryption key deserialization)
pub fn create_decryption_cache(user_decryption_key: Vec<u8>) -> Result<i32, String> {
    let user_decryption_key = UserDecryptionKey::from_bytes(&user_decryption_key)
        .expect("Hybrid Cipher: invalid user decryption key");

    let cache = DecryptionCache {
        user_decryption_key,
    };
    let id = NEXT_DECRYPTION_CACHE_ID.fetch_add(1, Ordering::Acquire);
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.insert(id, cache);
    Ok(id)
}

#[witgen]
pub fn destroy_decryption_cache(cache_handle: i32) -> Result<(), String> {
    let mut map = DECRYPTION_CACHE_MAP
        .write()
        .expect("A write mutex on decryption cache failed");
    map.remove(&cache_handle);
    Ok(())
}

#[witgen]
/// Decrypt ABE header
pub fn decrypt_hybrid_header(cache_handle: i32, encrypted_data: Vec<u8>) -> Result<String, String> {
    let map = DECRYPTION_CACHE_MAP
        .read()
        .expect("a read mutex on the decryption cache failed");
    let cache = map
        .get(&cache_handle)
        .expect("Hybrid Cipher: no decryption cache with handle");

    //
    // Recover header from `encrypted_bytes`
    let header_size_bytes: &[u8; 4] = &encrypted_data[0..4]
        .try_into()
        .map_err(|_| "byte arrays conversion failed")?;
    let header_size: usize = u32::from_be_bytes(*header_size_bytes) as usize;

    // Split header from encrypted data
    let header = &encrypted_data[4..(4 + header_size)];

    let header = internal_decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
        &cache.user_decryption_key,
        header,
    )
    .map_err(|e| e.to_string())?;

    Ok(header.symmetric_key.to_string())
}

#[witgen]
/// Decrypt symmetric block cipher
pub fn decrypt_hybrid_block(
    ciphertext: Vec<u8>,
    symmetric_key: Vec<u8>,
    uid: Vec<u8>,
    block_number: u64,
) -> Result<Vec<u8>, String> {
    let symmetric_key = <Aes256GcmCrypto as SymmetricCrypto>::Key::parse(symmetric_key)
        .map_err(|e| e.to_string())?;
    let cleartext = internal_decrypt_hybrid_block::<
        Gpsw<Bls12_381>,
        Aes256GcmCrypto,
        MAX_CLEAR_TEXT_SIZE,
    >(&symmetric_key, &uid, block_number as usize, &ciphertext)
    .map_err(|e| e.to_string())?;

    Ok(cleartext)
}

#[witgen]
/// Decrypt ABE-ciphertext (decrypt ABE header + decrypt AES)
pub fn decrypt(user_decryption_key: String, encrypted_data: Vec<u8>) -> Result<String, String> {
    let user_key = UserDecryptionKey::from_bytes(
        &hex::decode(user_decryption_key).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    //
    // Recover header from `encrypted_bytes`
    let header_size_bytes: [u8; 4] = encrypted_data[0..4]
        .try_into()
        .map_err(|_| "byte arrays conversion failed")?;
    let header_size: usize = u32::from_be_bytes(header_size_bytes) as usize;

    // Split header from encrypted data
    let header = &encrypted_data[4..(4 + header_size)];
    let encrypted_block = &encrypted_data[(4 + header_size)..];

    let header =
        internal_decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(&user_key, header)
            .map_err(|e| e.to_string())?;

    let cleartext =
        internal_decrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
            &header.symmetric_key,
            &header.meta_data.uid,
            0,
            encrypted_block,
        )
        .map_err(|e| e.to_string())?;

    String::from_utf8(cleartext).map_err(|e| e.to_string())
}

#[witgen]
/// Generate a delegate user decryption key for the access policy
pub fn delegate_user_decryption_key(
    delegation_key: Vec<u8>,
    user_decryption_key: String,
    policy: Vec<u8>,
    access_policy: Option<String>,
) -> Result<String, String> {
    let policy = &serde_json::from_slice(&policy).map_err(|e| e.to_string())?;
    let access_policy = match access_policy {
        Some(access_policy) => {
            AccessPolicy::from_boolean_expression(&access_policy).map_err(|e| e.to_string())?
        }
        None => AccessPolicy::All,
    };

    let delegation_key = DelegationKey::from_bytes(&delegation_key).map_err(|e| e.to_string())?;
    let user_key = UserDecryptionKey::from_bytes(
        &hex::decode(user_decryption_key).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    let engine = Engine::<Gpsw<Bls12_381>>::new();
    let delegation_key = engine
        .delegate_user_key(policy, &delegation_key, &user_key, &access_policy)
        .map_err(|e| e.to_string())?
        .to_string();
    Ok(delegation_key)
}

#[witgen]
/// Rotating ABE attributes
pub fn rotate_attributes(policy: Vec<u8>, attributes: Vec<Attribute>) -> Result<Vec<u8>, String> {
    let mut policy: crate::core::policy::Policy =
        serde_json::from_slice(&policy).map_err(|e| e.to_string())?;

    for input_attribute in attributes {
        let attribute = attr(&input_attribute.axis_name, &input_attribute.attribute);
        policy.rotate(&attribute).map_err(|e| e.to_string())?;
    }
    let new_policy = serde_json::to_vec(&policy).map_err(|e| e.to_string())?;

    Ok(new_policy)
}
