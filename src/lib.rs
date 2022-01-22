#![allow(clippy::type_complexity)]

pub mod bilinear_map;
pub mod error;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod gpsw;
pub mod hybrid_crypto;
pub mod msp;
pub mod policy;
pub mod public_key;

use std::convert::TryFrom;

use error::FormatErr;
use gpsw::{AbeScheme, AsBytes};
use policy::{AccessPolicy, Attribute, Policy};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

#[derive(Clone)]
pub struct Engine<S: AbeScheme> {
    pub pg: Policy,
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
    #[must_use]
    pub fn new(pg: &Policy) -> Self {
        Self {
            pg: (*pg).clone(),
            sch: S::default(),
        }
    }

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
        self.sch.generate_master_key(self.pg.max_attr())
    }

    pub fn generate_user_key(
        &self,
        priv_key: &S::MasterPrivateKey,
        access_policy: &AccessPolicy,
    ) -> Result<S::UserDecryptionKey, FormatErr> {
        let msp = self.pg.to_msp(access_policy)?;
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
            _ => Some(self.pg.to_msp(access_policy)?),
        };
        self.sch.key_delegation(&msp, user_key, del_key)
    }

    pub fn decrypt(
        &self,
        enc: &S::CipherText,
        key: &S::UserDecryptionKey,
    ) -> Result<Option<S::PlainText>, FormatErr> {
        self.sch.decrypt(enc, key)
    }

    /// Generate a random clear text and corresponding cipher text
    pub fn random_cleartext_ciphertext(
        &self,
        attrs: &[Attribute],
        pub_key: &S::MasterPublicKey,
    ) -> Result<(S::PlainText, S::CipherText), FormatErr> {
        let random_plain = self.sch.generate_random_plaintext()?;
        let attrs = attrs
            .iter()
            .filter_map(|a| {
                self.pg
                    .attribute_to_int
                    .get(a)
                    .and_then(std::collections::BinaryHeap::peek)
            })
            .copied()
            .collect::<Vec<_>>();
        let ciphertext = self.sch.encrypt(&random_plain, &attrs, pub_key)?;
        Ok((random_plain, ciphertext))
    }

    pub fn generate_symmetric_key(
        &self,
        attrs: &[Attribute],
        pub_key: &S::MasterPublicKey,
    ) -> Result<([u8; 32], Vec<u8>), FormatErr> {
        let (plaintext, ciphertext) = self.random_cleartext_ciphertext(attrs, pub_key)?;

        let hasher = Shake256::default();
        let mut sk = [0_u8; 32];
        let symkey = hasher
            .chain(&plaintext.as_bytes()?)
            .finalize_xof()
            .read_boxed(32)
            .into_vec();
        sk.copy_from_slice(&symkey[..]);
        Ok((sk, ciphertext.as_bytes()?))
    }

    // Update an attribute
    pub fn update(&mut self, attr: &Attribute) -> Result<(), FormatErr> {
        self.pg.update(attr)
    }
}

#[cfg(test)]
mod policy_tests;

#[cfg(test)]
mod msp_tests;

#[cfg(test)]
mod demo;
