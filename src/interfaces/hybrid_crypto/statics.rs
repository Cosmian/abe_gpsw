use cosmian_crypto_base::{
    hybrid_crypto::{Block, Header, Metadata},
    symmetric_crypto::SymmetricCrypto,
};

use crate::{
    core::gpsw::AbeScheme,
    interfaces::{
        asymmetric_crypto::{AbeCrypto, EncryptionParameters},
        policy::{Attribute, Policy},
    },
};

/// An EncryptedHeader returned by the `encrypt_hybrid_header` function
pub struct EncryptedHeader<S>
where
    S: SymmetricCrypto,
{
    pub symmetric_key: S::Key,
    pub encrypted_header_bytes: Vec<u8>,
}

/// An ClearTextHeader returned by the `decrypt_hybrid_header` function
pub struct ClearTextHeader<S>
where
    S: SymmetricCrypto,
{
    pub symmetric_key: S::Key,
    pub meta_data: Metadata,
}

/// Generate an encrypted header
/// for a resource encrypted using an hybrid crypto scheme.
///
/// A random symmetric key is generated for the specified symmetric scheme,
/// encrypted using the public key of the ABE scheme and policy attributes
/// then pre-pended to the symmetrically encrypted metadata
pub fn encrypt_hybrid_header<A, S>(
    policy: &Policy,
    public_key: &A::MasterPublicKey,
    attributes: &[Attribute],
    meta_data: Metadata,
) -> anyhow::Result<EncryptedHeader<S>>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    let attributes = attributes.to_vec();
    let header = Header::<AbeCrypto<A>, S>::generate(
        public_key,
        Some(&EncryptionParameters {
            policy: policy.clone(),
            policy_attributes: attributes,
        }),
        meta_data,
    )?;
    let symmetric_key = header.symmetric_key().to_owned();
    let header_bytes = header.as_bytes()?;
    Ok(EncryptedHeader {
        symmetric_key,
        encrypted_header_bytes: header_bytes,
    })
}

/// Decrypt with a user decryption key an encrypted header
/// of a resource encrypted using an hybrid crypto scheme.
pub fn decrypt_hybrid_header<A, S>(
    user_decryption_key: &A::UserDecryptionKey,
    encrypted_header: &[u8],
) -> anyhow::Result<ClearTextHeader<S>>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    let header = Header::<AbeCrypto<A>, S>::from_bytes(encrypted_header, user_decryption_key)?;
    Ok(ClearTextHeader {
        symmetric_key: header.symmetric_key().to_owned(),
        meta_data: header.meta_data().to_owned(),
    })
}

/// The overhead due to symmetric encryption when encrypting a block.
/// This is a constant
pub fn symmetric_encryption_overhead<S, const MAX_CLEAR_TEXT_SIZE: usize>() -> usize
where
    S: SymmetricCrypto,
{
    Block::<S, MAX_CLEAR_TEXT_SIZE>::ENCRYPTION_OVERHEAD
}

/// Encrypt data symmetrically in a block.
///
/// The `uid` should be different for every resource  and `block_number`
/// different for every block. They are part of the AEAD of the symmetric scheme
/// if any.
///
/// The `MAX_CLEAR_TEXT_SIZE` fixes the maximum clear text that can fit in a
/// block. That value should be kept identical for all blocks of a resource.
///
/// The nonce, if any, occupies the first bytes of the encrypted block.
pub fn encrypt_hybrid_block<A, S, const MAX_CLEAR_TEXT_SIZE: usize>(
    symmetric_key: &S::Key,
    uid: &[u8],
    block_number: usize,
    clear_text: &[u8],
) -> anyhow::Result<Vec<u8>>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    let mut block = Block::<S, MAX_CLEAR_TEXT_SIZE>::new();
    if clear_text.len() > MAX_CLEAR_TEXT_SIZE {
        anyhow::bail!(
            "The data to encrypt is too large: {} bytes, max size: {} ",
            clear_text.len(),
            MAX_CLEAR_TEXT_SIZE
        );
    }
    block.write(0, clear_text)?;

    block.to_encrypted_bytes(symmetric_key, uid, block_number)
}

/// Symmetrically Decrypt encrypted data in a block.
///
/// The `uid` and `block_number` are part of the AEAD
/// of the crypto scheme (when applicable)
pub fn decrypt_hybrid_block<A, S, const MAX_CLEAR_TEXT_SIZE: usize>(
    symmetric_key: &S::Key,
    uid: &[u8],
    block_number: usize,
    encrypted_bytes: &[u8],
) -> anyhow::Result<Vec<u8>>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    if encrypted_bytes.len() > Block::<S, MAX_CLEAR_TEXT_SIZE>::MAX_ENCRYPTED_LENGTH {
        anyhow::bail!(
            "The encrypted data to decrypt is too large: {} bytes, max size: {} ",
            encrypted_bytes.len(),
            Block::<S, MAX_CLEAR_TEXT_SIZE>::MAX_ENCRYPTED_LENGTH
        );
    }
    let block = Block::<S, MAX_CLEAR_TEXT_SIZE>::from_encrypted_bytes(
        encrypted_bytes,
        symmetric_key,
        uid,
        block_number,
    )?;
    Ok(block.clear_text_owned())
}
