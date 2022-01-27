#![allow(dead_code)]
use std::convert::TryFrom;

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

/// The engine si the main entry point for the core ABE functionalities.
/// It supplies a simple API that lets generate keys, encrypt and decrypt
/// messages as well as rotate Policy attributes.
///
/// In addition, two methods are supplied to generate random symmetric keys and
/// their corresponding cipher texts which are suitable for use in a hybrid
/// encryption scheme.
#[derive(Clone)]
pub struct Engine<S: AbeScheme> {
    pub policy: Policy,
    sch: S,
}

impl<S: AbeScheme> TryFrom<&[u8]> for Engine<S> {
    type Error = FormatErr;

    fn try_from(attributes: &[u8]) -> Result<Self, Self::Error> {
        let pg: Policy = serde_json::from_slice(attributes)?;
        Ok(Self::new(&pg))
    }
}

impl<S: AbeScheme> Engine<S> {
    /// Instantiate a new ABE engine for the given Plicy
    #[must_use]
    pub fn new(policy: &Policy) -> Self {
        Self {
            policy: (*policy).clone(),
            sch: S::default(),
        }
    }

    /// Generate the master authority keys for supplied Policy
    pub fn generate_master_key(
        &self,
    ) -> Result<
        (
            S::MasterPrivateKey,
            S::MasterPublicKey,
            S::MasterPublicDelegationKey,
        ),
        FormatErr,
    > {
        self.sch.generate_master_key(self.policy.max_attr())
    }

    pub fn generate_user_key(
        &self,
        priv_key: &S::MasterPrivateKey,
        access_policy: &AccessPolicy,
    ) -> Result<S::UserDecryptionKey, FormatErr> {
        let msp = self.policy.to_msp(access_policy)?;
        self.sch.key_generation(&msp, priv_key)
    }

    // allows a user to generate a new key for a more restrictive policy
    // A more restrictive policy is a policy for which when it is satisfy, the less
    // restrictive also. In other words, we can only modify a policy by changing
    // an `Or` node by either an `And` or replace it by one of its child.
    // Remark: It is also possible to merge 2 keys by `Or` node, this latter
    // functionality is not yet supported
    pub fn delegate_user_key(
        &self,
        del_key: &S::MasterPublicDelegationKey,
        user_key: &S::UserDecryptionKey,
        access_policy: &AccessPolicy,
    ) -> Result<S::UserDecryptionKey, FormatErr> {
        let msp = match access_policy {
            AccessPolicy::All => None,
            _ => Some(self.policy.to_msp(access_policy)?),
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
        plain_text: &S::PlainText,
        attributes: &[Attribute],
        public_key: &S::MasterPublicKey,
    ) -> Result<S::CipherText, FormatErr> {
        let attributes = self.policy.attributes_values(attributes);
        self.sch.encrypt(plain_text, &attributes, public_key)
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
        attrs: &[Attribute],
        pub_key: &S::MasterPublicKey,
        symmetric_key_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), FormatErr> {
        let random = self.random_message()?;
        // Use a hash of the plaintext bytes as the symmetric key
        let sym_key = Shake256::default()
            .chain(&random.as_bytes()?)
            .finalize_xof()
            .read_boxed(symmetric_key_len)
            .into_vec();
        let enc_sym_key = self.encrypt(&random, attrs, pub_key)?.as_bytes()?;
        Ok((sym_key, enc_sym_key))
    }

    /// Decrypt a symmetric key generated with `generate_symmetric_key()`
    pub fn decrypt_symmetric_key(
        &self,
        decryption_key: &S::UserDecryptionKey,
        encrypted_symmetric_key: &[u8],
        symmetric_key_len: usize,
    ) -> Result<Vec<u8>, FormatErr> {
        let sym_key = self
            .decrypt(
                &S::CipherText::from_bytes(encrypted_symmetric_key)?,
                decryption_key,
            )?
            .ok_or(FormatErr::InvalidEncryptedData)?
            .as_bytes()?;
        // Use a hash of the plaintext bytes as the symmetric key
        Ok(Shake256::default()
            .chain(&sym_key)
            .finalize_xof()
            .read_boxed(symmetric_key_len)
            .into_vec())
    }

    // Rotate a Policy Attribute
    pub fn rotate(&mut self, attr: &Attribute) -> Result<(), FormatErr> {
        self.policy.update(attr)
    }
}
