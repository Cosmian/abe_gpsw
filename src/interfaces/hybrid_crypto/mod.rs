mod cipher;

pub use cipher::HybridCipher;
use cosmian_crypto_base::asymmetric::AsymmetricCrypto;
use cosmian_crypto_base::hybrid_crypto::Block;
use cosmian_crypto_base::symmetric_crypto::Key;
use cosmian_crypto_base::{
    hybrid_crypto::{Header, Metadata},
    symmetric_crypto::SymmetricCrypto,
};

use crate::core::gpsw::AbeScheme;
use crate::interfaces::{
    asymmetric_crypto::AbeCrypto,
    policy::{Attribute, Policy},
};

pub struct EncryptedHeader {
    pub symmetric_key: Vec<u8>,
    pub header_bytes: Vec<u8>,
}

pub fn encrypt_hybrid_header<A, S>(
    policy: Policy,
    public_key: A::MasterPublicKey,
    attributes: &[Attribute],
    meta_data: Metadata,
) -> anyhow::Result<EncryptedHeader>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    let attributes = attributes.to_vec();
    let engine = AbeCrypto::<A>::new().set_scheme_parameters(policy);
    //let uid = meta_data.sec.clone();
    let header =
        Header::<AbeCrypto<A>, S>::generate(&engine, &public_key, Some(&attributes), meta_data)?;
    let symmetric_key = header.symmetric_key().to_owned();
    let header_bytes = header.as_bytes()?;
    Ok(EncryptedHeader {
        symmetric_key: symmetric_key.as_bytes(),
        header_bytes,
    })
}

pub fn symmetric_encryption_overhead<S, const MAX_CLEAR_TEXT_SIZE: usize>() -> usize
where
    S: SymmetricCrypto,
{
    Block::<S, MAX_CLEAR_TEXT_SIZE>::ENCRYPTION_OVERHEAD
}

pub fn encrypt_hybrid_block<A, S, const MAX_CLEAR_TEXT_SIZE: usize>(
    symmetric_key: &S::Key,
    uid: &[u8],
    block_number: usize,
    data: &[u8],
) -> anyhow::Result<Vec<u8>>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    let mut block = Block::<S, MAX_CLEAR_TEXT_SIZE>::new();
    if data.len() > MAX_CLEAR_TEXT_SIZE {
        anyhow::bail!(
            "Tha data to encrypt is too large: {} bytes, max size: {} ",
            data.len(),
            MAX_CLEAR_TEXT_SIZE
        );
    }
    block.write(0, data)?;

    let symmetric_crypto = <S as SymmetricCrypto>::new();
    block.to_encrypted_bytes(&symmetric_crypto, symmetric_key, uid, block_number)
}
