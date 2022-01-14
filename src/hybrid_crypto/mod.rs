use std::convert::TryFrom;

use cosmian_crypto_base::{
    asymmetric::AsymmetricCrypto,
    hybrid_crypto::{header::UID_LENGTH, Block, Header},
    symmetric_crypto::{
        aes_256_gcm_pure::{Aes256GcmCrypto, Key, KEY_LENGTH, MAC_LENGTH, NONCE_LENGTH},
        SymmetricCrypto,
    },
};
use tracing::{debug, trace};

use crate::{
    bilinear_map::bls12_381::Bls12_381,
    error::FormatErr,
    gpsw::{
        abe::{Gpsw, GpswDecryptionKey, GpswMasterPrivateKey, GpswMasterPublicDelegationKey},
        AsBytes,
    },
    policy::{AccessPolicy, Attribute, Policy},
    public_key::{AbeCrypto, AbePrivateKey, AbePublicKey},
    Engine,
};

pub const ATTRIBUTES_FIELD_SIZE: usize = 4; // size of integer: 4 bytes
pub const SYMMETRIC_CRYPTO_OVERHEAD: usize = NONCE_LENGTH + MAC_LENGTH;

type Abe = AbeCrypto<Gpsw<Bls12_381>>;
type Bl = Block<Aes256GcmCrypto>;
type Hdr = Header<AbeCrypto<Gpsw<Bls12_381>>, Aes256GcmCrypto>;

/// Generate a user decryption key for the given master key and access policy
pub fn generate_user_decryption_key(
    private_key: &[u8],
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<String, FormatErr> {
    //
    // Get Master key from bytes array
    //
    let mk = GpswMasterPrivateKey::<Bls12_381>::from_bytes(private_key)?;

    //
    // Build engine from configuration file
    //
    let engine = Engine::<Gpsw<Bls12_381>>::new(policy);

    //TODO maybe add a check that the proposed policy is compatible with the policy

    //
    // Generate key pair for this specific policy: construct the policy from the
    // given attributes
    //
    let decryption_key = engine.generate_user_key(&mk, access_policy)?;

    Ok(decryption_key.to_string())
}

/// Generate a delegation decryption key for the given master key and access
/// policy
pub fn generate_delegation_key(
    delegation_key: &[u8],
    user_decryption_key: &str,
    access_policy: &AccessPolicy,
    policy: &Policy,
) -> Result<String, FormatErr> {
    //
    // Get Master key from bytes array
    //
    let user_decryption_key = GpswDecryptionKey::<Bls12_381>::from_bytes(
        &hex::decode(user_decryption_key).map_err(|e| FormatErr::Deserialization(e.to_string()))?,
    )?;
    let delegation_key = GpswMasterPublicDelegationKey::<Bls12_381>::from_bytes(delegation_key)?;

    //
    // Build engine from configuration file
    //
    let engine = Engine::<Gpsw<Bls12_381>>::new(policy);

    //
    // Generate key pair for this specific policy: construct the policy from the
    // given attributes
    //
    let decryption_key =
        engine.delegate_user_key(&delegation_key, &user_decryption_key, access_policy)?;

    Ok(decryption_key.to_string())
}

/// Revoke an attributes-list
pub fn revoke_attributes(
    attributes: &[Attribute],
    policy: &Policy,
) -> Result<Engine<Gpsw<Bls12_381>>, FormatErr> {
    //
    // Build engine from configuration file
    //
    let mut engine = Engine::<Gpsw<Bls12_381>>::new(policy);

    //
    // Revoking attributes is equivalent to renew integer-attribute value
    //
    for attr in attributes {
        engine.update(attr)?;
    }
    Ok(engine)
}

/// Generate a new random point on GT,
///  encrypt the point for the given access policy
///
/// Returns the shake 256 hash of the point and the encrypted point
pub fn generate_symmetric_key_and_header(
    resource_uid: &[u8; UID_LENGTH],
    public_key: &[u8],
    policy_attributes: &[Attribute],
    policy: &Policy,
) -> Result<([u8; KEY_LENGTH], Vec<u8>), FormatErr> {
    //
    // Build engine from configuration file
    //
    trace!("Build engine from policy");
    let engine = Engine::<Gpsw<Bls12_381>>::new(policy);

    //
    // Generate and encrypt the symmetric key according to ABE attributes
    //
    trace!("Deserialize public key from bytes");
    let public_key = AbePublicKey::<Gpsw<Bls12_381>>::try_from(public_key)
        .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
    //TODO maybe add a check that the proposed policy is compatible with the policy
    let symmetric_key = engine.generate_symmetric_key(policy_attributes, &public_key.0)?;

    //
    // Format encrypted key to Header format
    //
    let sym_key = Aes256GcmCrypto::generate_key_from_rnd(&symmetric_key.0)
        .map_err(|e| FormatErr::SymmetricKeyGeneration(e.to_string()))?;
    let asymmetric_header = Hdr::new(resource_uid.to_owned(), sym_key);
    let attributes_length = i32::try_from(policy_attributes.len())?;
    let mut encrypted_header = attributes_length.to_be_bytes().to_vec();
    let header = asymmetric_header
        .to_bytes(symmetric_key.1)
        .map_err(|e| FormatErr::Serialization(e.to_string()))?;
    trace!("Encryption: header size: {}", header.len());
    encrypted_header.extend_from_slice(&header[..]);

    Ok((symmetric_key.0, encrypted_header))
}

/// Encrypt an `input` using an hybrid encryption scheme ABE+AES256GCM
///
/// - `symmetric_key` is the hash of the random GT point used as a 256 bit AES
///   key
/// - `resource_uid` is part of the AES AEAD and uniquely identifies the
///   encrypted resource
/// - `first_block_number` is also part on the AES AEAD and is increased on
///   every AES block (4096 bytes)
///
/// Returns the encrypted data (pre-pended with the header) and the last AES
/// block number
pub fn encrypt(
    symmetric_key: &[u8],
    resource_uid: &[u8; UID_LENGTH],
    input: &[u8],
    first_block_number: usize,
) -> Result<(Vec<u8>, usize), FormatErr> {
    let symmetric_key =
        Key::try_from(symmetric_key).map_err(|e| FormatErr::Deserialization(e.to_string()))?;

    let header = Hdr::new(resource_uid.to_owned(), symmetric_key);
    let blocks = input.len() / Bl::MAX_CLEAR_TEXT_LENGTH;
    let nb_blocks = if input.len() % Bl::MAX_CLEAR_TEXT_LENGTH == 0 {
        blocks
    } else {
        blocks + 1
    };

    //
    // AES-GCM symmetric encryption
    //
    let symmetric = Aes256GcmCrypto::new();
    let mut output = Vec::new();
    for block_number in 0..nb_blocks {
        let start = Bl::MAX_CLEAR_TEXT_LENGTH * block_number;
        let tmp_end = Bl::MAX_CLEAR_TEXT_LENGTH * (block_number + 1);

        let end = if input.len() > start && input.len() < tmp_end {
            input.len()
        } else {
            tmp_end
        };
        debug!("Take input from {} and {}", start, end);
        let mut block = Bl::new();
        block
            .write(0, &input[start..end])
            .map_err(|e| FormatErr::SymmetricEncryption(e.to_string()))?;

        let cipher_text = block
            .to_encrypted_bytes(
                &symmetric,
                &header.symmetric_key,
                &header.uid,
                first_block_number + block_number,
            )
            .map_err(|e| FormatErr::SymmetricEncryption(e.to_string()))?;
        output.extend_from_slice(&cipher_text[..]);
    }
    Ok((output, first_block_number + nb_blocks))
}

fn build_abe(encrypted_data: &[u8]) -> Result<Abe, FormatErr> {
    trace!("Encrypted data: {:?}", &encrypted_data);
    if encrypted_data.len() <= ATTRIBUTES_FIELD_SIZE {
        return Err(FormatErr::InvalidEncryptedDataSize(
            ATTRIBUTES_FIELD_SIZE.to_string(),
        ))
    }
    //
    // Read the number of attributes (required to know encrypted message length)
    //
    let mut raw_attributes = [0_u8; ATTRIBUTES_FIELD_SIZE];
    raw_attributes.copy_from_slice(&encrypted_data[..ATTRIBUTES_FIELD_SIZE]);
    let nb_attributes = u32::from_be_bytes(raw_attributes);
    if nb_attributes >= u32::from(u16::MAX) {
        return Err(FormatErr::DecodingAttributeNumber)
    }

    let fake_attributes = vec![0; nb_attributes as usize];
    trace!("Data was encrypted using {} attributes.", nb_attributes);

    // Initialized crypto primitives
    let abe = Abe::new_attrs(&fake_attributes);
    Ok(abe)
}

pub fn get_header_and_data(encrypted_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FormatErr> {
    let header_size = Hdr::length(&build_abe(encrypted_data)?);
    let (header, data) = encrypted_data.split_at(ATTRIBUTES_FIELD_SIZE + header_size);
    Ok((header.into(), data.into()))
}

/// User_decryption_key
pub fn decrypt_header(private_key: &[u8], encrypted_header: &[u8]) -> Result<Hdr, FormatErr> {
    trace!("Starting header decryption");
    let abe = build_abe(encrypted_header)?;
    trace!(
        "Build abe crypto OK. Parsing user decryption key: {:?}",
        private_key
    );
    let private_key = AbePrivateKey::<Gpsw<Bls12_381>>::from_bytes(private_key)?;
    trace!("Build private pair OK.");

    let header_size = Hdr::length(&abe);
    trace!("Decryption: header expected size: {}", header_size);

    //
    // Read and decrypt symmetric key found in the header.
    //
    let mut encrypted_header_slice = vec![0_u8; header_size];
    encrypted_header_slice.copy_from_slice(&encrypted_header[ATTRIBUTES_FIELD_SIZE..]);
    let header = Hdr::from_encrypted_bytes(&encrypted_header_slice[..], &abe, &private_key);
    trace!("Get header from encrypted bytes");
    if header.is_err() {
        return Err(FormatErr::InsuffisentAccessPolicy)
    }
    header.map_err(|e| FormatErr::AsymmetricDecryption(e.to_string()))
}

pub fn symmetric_decryption(
    symmetric_key: &[u8],
    uid: &[u8; UID_LENGTH],
    input: &[u8],
    first_block_number: usize,
) -> Result<Vec<u8>, FormatErr> {
    let symmetric = Aes256GcmCrypto::new();

    let blocks = input.len() / Bl::MAX_BLOCK_LENGTH;
    let nb_blocks = if input.len() % Bl::MAX_BLOCK_LENGTH == 0 {
        blocks
    } else {
        blocks + 1
    };
    trace!(
        "Encrypted input will be read in {} blocks of {} bytes",
        nb_blocks,
        Bl::MAX_BLOCK_LENGTH
    );

    let sk = Key::try_from(symmetric_key).map_err(|e| FormatErr::Deserialization(e.to_string()))?;
    //
    // Then decrypt input by block
    //
    let mut output = Vec::new();
    for block_number in 0..nb_blocks {
        let start = Bl::MAX_BLOCK_LENGTH * block_number;
        let tmp_end = Bl::MAX_BLOCK_LENGTH * (block_number + 1);

        let end = if input.len() > start && input.len() < tmp_end {
            input.len()
        } else {
            tmp_end
        };
        trace!("Take input from {} and {}", start, end);
        let block = Bl::from_encrypted_bytes(
            &input[start..end],
            &symmetric,
            &sk,
            uid,
            first_block_number + block_number,
        )
        .map_err(|e| FormatErr::SymmetricDecryption(e.to_string()))?;
        output.extend_from_slice(block.clear_text());
    }
    Ok(output)
}

/// Decrypt an `input` using an hybrid encryption scheme ABE+AES256GCM
///
/// - `user_decryption_key` is the user key holding an access policy
/// - `encrypted_header` is the encypted symmetric key
/// - `input` is the AESG GCM encrypted data
/// - `first_block_number` is part on the AES AEAD and is increased on every AES
///   block (4096 bytes)
///
/// Returns the encrypted data (pre-pended with the header) ant the last AES
/// block number
pub fn decrypt(
    user_decryption_key: &[u8],
    encrypted_header: &[u8],
    input: &[u8],
    first_block_number: usize,
) -> Result<Vec<u8>, FormatErr> {
    trace!("Starting ABE decrypt");
    let header = decrypt_header(user_decryption_key, encrypted_header)?;
    let symmetric_key = header.symmetric_key.0;
    let uid = header.uid;
    symmetric_decryption(&symmetric_key, &uid, input, first_block_number)
}

#[cfg(test)]
mod tests;
