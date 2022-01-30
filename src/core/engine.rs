use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::{
    core::{
        gpsw::{AbeScheme, AsBytes},
        policy::{AccessPolicy, Attribute, Policy},
    },
    error::FormatErr,
};

/// The engine is the main entry point for the core ABE functionalities.
///
/// It supplies a simple API that lets generate keys, encrypt and decrypt
/// messages.
///
/// In addition, two methods are supplied to generate random symmetric keys and
/// their corresponding cipher texts which are suitable for use in a hybrid
/// encryption scheme.
#[derive(Clone)]
pub struct Engine<S: AbeScheme> {
    sch: S,
}

impl<S: AbeScheme> Engine<S> {
    /// Instantiate a new ABE engine for the given Plicy
    #[must_use]
    pub fn new() -> Self {
        Self { sch: S::default() }
    }

    /// Generate the master authority keys for supplied Policy
    pub fn generate_master_key(
        &self,
        policy: &Policy,
    ) -> Result<
        (
            S::MasterPrivateKey,
            S::MasterPublicKey,
            S::MasterPublicDelegationKey,
        ),
        FormatErr,
    > {
        self.sch.generate_master_key(policy.max_attr())
    }

    pub fn generate_user_key(
        &self,
        policy: &Policy,
        priv_key: &S::MasterPrivateKey,
        access_policy: &AccessPolicy,
    ) -> Result<S::UserDecryptionKey, FormatErr> {
        let msp = policy.to_msp(access_policy)?;
        self.sch.key_generation(&msp, priv_key)
    }

    /// Allows a user to generate a new key for a more restrictive policy
    ///
    /// A more restrictive policy is a policy for which when it is satisfy, the less
    /// restrictive also. In other words, we can only modify a policy by changing
    /// an `Or` node by either an `And` or replace it by one of its child.
    ///
    /// Remark: It is also possible to merge 2 keys by `Or` node, this latter
    /// functionality is not yet supported
    // Not exposed to public FFI API yet: hence he dead_code
    #[allow(dead_code)]
    pub fn delegate_user_key(
        &self,
        policy: &Policy,
        del_key: &S::MasterPublicDelegationKey,
        user_key: &S::UserDecryptionKey,
        access_policy: &AccessPolicy,
    ) -> Result<S::UserDecryptionKey, FormatErr> {
        let msp = match access_policy {
            AccessPolicy::All => None,
            _ => Some(policy.to_msp(access_policy)?),
        };
        self.sch.key_delegation(&msp, user_key, del_key)
    }

    /// Generate a random point on GT
    pub fn random_message(&self) -> Result<S::PlainText, FormatErr> {
        self.sch.generate_random_plaintext()
    }

    /// Encrypt a plain test (a pont on GT) with the given list of attributes
    pub fn encrypt(
        &self,
        policy: &Policy,
        public_key: &S::MasterPublicKey,
        attributes: &[Attribute],
        plain_text: &S::PlainText,
    ) -> Result<S::CipherText, FormatErr> {
        let int_attributes = policy.attributes_values(attributes)?;
        self.sch.encrypt(plain_text, &int_attributes, public_key)
    }

    /// Decrypt a cipher text returning the point on GT
    pub fn decrypt(
        &self,
        enc: &S::CipherText,
        key: &S::UserDecryptionKey,
    ) -> Result<Option<S::PlainText>, FormatErr> {
        self.sch.decrypt(enc, key)
    }

    /// Generate a random symmetric key of `symmetric_key_len` to be used n
    /// hybrid encryption scheme and its ABE encrypted version with the
    /// supplied `attributes`
    pub fn generate_symmetric_key(
        &self,
        policy: &Policy,
        public_key: &S::MasterPublicKey,
        attrs: &[Attribute],
        symmetric_key_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), FormatErr> {
        let random = self.random_message()?;
        let enc_sym_key = self
            .encrypt(policy, public_key, attrs, &random)?
            .as_bytes()?;
        // Use a hash of the plaintext bytes as the symmetric key
        let sym_key = Shake256::default()
            .chain(&random.as_bytes()?)
            .finalize_xof()
            .read_boxed(symmetric_key_len)
            .into_vec();
        Ok((sym_key, enc_sym_key))
    }

    /// Decrypt a symmetric key generated with `generate_symmetric_key()`
    pub fn decrypt_symmetric_key(
        &self,
        decryption_key: &S::UserDecryptionKey,
        encrypted_symmetric_key: &[u8],
        symmetric_key_len: usize,
    ) -> Result<Vec<u8>, FormatErr> {
        let random = self
            .decrypt(
                &S::CipherText::from_bytes(encrypted_symmetric_key)?,
                decryption_key,
            )?
            .ok_or(FormatErr::InvalidEncryptedData)?;
        // Use a hash of the plaintext bytes as the symmetric key
        Ok(Shake256::default()
            .chain(&random.as_bytes()?)
            .finalize_xof()
            .read_boxed(symmetric_key_len)
            .into_vec())
    }
}
