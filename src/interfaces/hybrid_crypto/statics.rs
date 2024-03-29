use std::convert::{TryFrom, TryInto};

use cosmian_crypto_base::{
    entropy::CsRng,
    symmetric_crypto::{nonce::NonceTrait, Block, BytesScanner, Metadata, SymmetricCrypto},
    typenum::Unsigned,
    CryptoBaseError, KeyTrait,
};

use crate::{
    core::{gpsw::AbeScheme, Engine},
    error::FormatErr,
    interfaces::abe_policy::{Attribute, Policy},
};

/// An `EncryptedHeader` returned by the `encrypt_hybrid_header` function
pub struct EncryptedHeader<S>
where
    S: SymmetricCrypto,
{
    pub symmetric_key: S::Key,
    pub encrypted_header_bytes: Vec<u8>,
}

impl<S: SymmetricCrypto> EncryptedHeader<S> {
    pub fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut bytes: Vec<u8> =
            u32::to_be_bytes(<<S as SymmetricCrypto>::Key as KeyTrait>::Length::to_u32())
                .try_into()?;
        bytes.extend_from_slice(&self.symmetric_key.to_bytes());
        bytes.extend_from_slice(&self.encrypted_header_bytes[..]);
        Ok(bytes)
    }

    pub fn try_from_bytes(header: &[u8]) -> Result<Self, FormatErr> {
        if header.len() < 4 {
            return Err(FormatErr::InvalidHeaderSize(header.len()));
        }
        let symmetric_key_len: [u8; 4] = header[0..4].try_into()?;
        let symmetric_key_len = u32::from_be_bytes(symmetric_key_len) as usize;
        // Then split header between `symmetric_key` and `encrypted_symmetric_key`
        let symmetric_key_bytes: Vec<u8> = header[4..(4 + symmetric_key_len)].try_into()?;
        let encrypted_header_bytes: Vec<u8> = header[(4 + symmetric_key_len)..].try_into()?;

        Ok(Self {
            symmetric_key: S::Key::try_from_bytes(&symmetric_key_bytes)?,
            encrypted_header_bytes,
        })
    }
}

/// An `ClearTextHeader` returned by the `decrypt_hybrid_header` function
pub struct ClearTextHeader<S>
where
    S: SymmetricCrypto,
{
    pub symmetric_key: S::Key,
    pub meta_data: Metadata,
}

impl<S: SymmetricCrypto> ClearTextHeader<S> {
    pub fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut bytes: Vec<u8> =
            u32::to_be_bytes(<<S as SymmetricCrypto>::Key as KeyTrait>::Length::to_u32())
                .try_into()?;
        bytes.extend_from_slice(&self.symmetric_key.to_bytes());
        bytes.extend_from_slice(&self.meta_data.try_to_bytes()?);
        Ok(bytes)
    }

    pub fn try_from_bytes(header: &[u8]) -> Result<Self, FormatErr> {
        if header.len() < 4 {
            return Err(FormatErr::InvalidHeaderSize(header.len()));
        }
        let symmetric_key_len: [u8; 4] = header[0..4].try_into()?;
        let symmetric_key_len = u32::from_be_bytes(symmetric_key_len) as usize;
        // Then split header between `symmetric_key` and `meta_data`
        let symmetric_key_bytes: Vec<u8> = header[4..(4 + symmetric_key_len)].try_into()?;
        let meta_data_bytes: Vec<u8> = header[(4 + symmetric_key_len)..].try_into()?;

        Ok(Self {
            symmetric_key: S::Key::try_from_bytes(&symmetric_key_bytes)?,
            meta_data: Metadata::try_from_bytes(&meta_data_bytes)?,
        })
    }
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
    meta_data: Option<Metadata>,
) -> Result<EncryptedHeader<S>, FormatErr>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    let engine = Engine::<A>::new();
    let (sk_bytes, encrypted_sk) = engine.generate_symmetric_key(
        policy,
        public_key,
        attributes,
        <S::Key as KeyTrait>::Length::to_usize(),
    )?;
    let symmetric_key = S::Key::try_from_bytes(&sk_bytes)?;

    // convert to bytes
    // ..size
    let mut header_bytes = u32_len(&encrypted_sk)?.to_vec();
    // ...bytes
    header_bytes.extend(&encrypted_sk);
    if let Some(meta) = meta_data {
        // Nonce
        let nonce = S::Nonce::new(&mut CsRng::new());
        header_bytes.extend_from_slice(nonce.as_slice());

        // Encrypted metadata
        let encrypted_metadata = S::encrypt(&symmetric_key, &meta.try_to_bytes()?, &nonce, None)?;
        // ... size
        header_bytes.extend(u32_len(&encrypted_metadata)?);
        // ... bytes
        header_bytes.extend(encrypted_metadata);
    }

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
) -> Result<ClearTextHeader<S>, FormatErr>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    if encrypted_header.len() < 4 {
        return Err(FormatErr::InvalidHeaderSize(encrypted_header.len()));
    }
    // scan the input bytes
    let mut scanner = BytesScanner::new(encrypted_header);

    // encrypted symmetric key size
    let encrypted_symmetric_key_size = scanner
        .read_u32()
        .map_err(|e| FormatErr::CryptoError(e.to_string()))?
        as usize;
    let encrypted_symmetric_key = scanner
        .next(encrypted_symmetric_key_size)
        .map_err(|e| FormatErr::CryptoError(e.to_string()))?
        .to_vec();

    // symmetric key
    let engine = Engine::<A>::new();
    // let asymmetric_scheme = A::default();
    let symmetric_key = S::Key::try_from_bytes(&engine.decrypt_symmetric_key(
        user_decryption_key,
        &encrypted_symmetric_key,
        <S::Key as KeyTrait>::Length::to_usize(),
    )?)?;

    let meta_data = if scanner.has_more() {
        // Nonce
        let nonce = S::Nonce::try_from_bytes(
            scanner
                .next(S::Nonce::LENGTH)
                .map_err(|e| FormatErr::CryptoError(e.to_string()))?,
        )?;

        // encrypted metadata
        let encrypted_metadata_size = scanner
            .read_u32()
            .map_err(|e| FormatErr::CryptoError(e.to_string()))?
            as usize;

        // UID
        let encrypted_metadata = scanner
            .next(encrypted_metadata_size)
            .map_err(|e| FormatErr::CryptoError(e.to_string()))?;
        Metadata::try_from_bytes(&S::decrypt(
            &symmetric_key,
            encrypted_metadata,
            &nonce,
            None,
        )?)
        .map_err(|e| FormatErr::CryptoError(e.to_string()))?
    } else {
        Metadata::default()
    };

    Ok(ClearTextHeader {
        symmetric_key,
        meta_data,
    })
}

/// The overhead due to symmetric encryption when encrypting a block.
/// This is a constant
#[must_use]
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
    plaintext: &[u8],
) -> Result<Vec<u8>, FormatErr>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    if plaintext.is_empty() {
        return Err(FormatErr::EmptyPlaintext);
    }
    if plaintext.len() > MAX_CLEAR_TEXT_SIZE {
        return Err(FormatErr::InvalidSize(format!(
            "The data to encrypt is too large: {} bytes, max size: {} ",
            plaintext.len(),
            MAX_CLEAR_TEXT_SIZE
        )));
    }
    let mut block = Block::<S, MAX_CLEAR_TEXT_SIZE>::new();
    block.write(0, plaintext)?;

    //TODO: try passing an already instantiated CsRng
    Ok(block.to_encrypted_bytes(&mut CsRng::new(), symmetric_key, uid, block_number)?)
}

/// Symmetrically Decrypt encrypted data in a block.
///
/// The `uid` and `block_number` are part of the AEAD
/// of the crypto scheme (when applicable)
pub fn decrypt_hybrid_block<A, S, const MAX_CLEAR_TEXT_SIZE: usize>(
    symmetric_key: &S::Key,
    uid: &[u8],
    block_number: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>, FormatErr>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    if ciphertext.is_empty() {
        return Err(FormatErr::EmptyCiphertext);
    }
    if ciphertext.len() > Block::<S, MAX_CLEAR_TEXT_SIZE>::MAX_ENCRYPTED_LENGTH {
        return Err(FormatErr::InvalidSize(format!(
            "The encrypted data to decrypt is too large: {} bytes, max size: {} ",
            ciphertext.len(),
            Block::<S, MAX_CLEAR_TEXT_SIZE>::MAX_ENCRYPTED_LENGTH
        )));
    }

    let block = Block::<S, MAX_CLEAR_TEXT_SIZE>::from_encrypted_bytes(
        ciphertext,
        symmetric_key,
        uid,
        block_number,
    )?;
    Ok(block.clear_text_owned())
}

// Attempt getting the length of this slice as an u32 in 4 big endian bytes and
// return an error if it overflows
fn u32_len(slice: &[u8]) -> Result<[u8; 4], CryptoBaseError> {
    u32::try_from(slice.len())
        .map_err(|_| {
            CryptoBaseError::InvalidSize(
                "Slice of bytes is too big to fit in 2^32 bytes".to_string(),
            )
        })
        .map(u32::to_be_bytes)
}
