use std::marker::PhantomData;

use cosmian_crypto_base::{
    asymmetric::AsymmetricCrypto,
    hybrid_crypto::{Block, Header, Metadata},
    symmetric_crypto::SymmetricCrypto,
};

use crate::{
    core::{
        gpsw::AbeScheme,
        policy::{Attribute, Policy},
    },
    interfaces::asymmetric_crypto::{AbeCrypto, EncryptionParameters},
};

pub struct HybridCipher<A, S>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    symmetric_key: S::Key,
    header_bytes: Vec<u8>,
    uid: Vec<u8>,
    phantom: PhantomData<A>,
}

impl<A, S> HybridCipher<A, S>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    pub fn instantiate(
        policy: Policy,
        public_key: A::MasterPublicKey,
        attributes: &[Attribute],
        meta_data: Metadata,
    ) -> anyhow::Result<Self> {
        let attributes = attributes.to_vec();
        let engine = AbeCrypto::<A>::new();
        let uid = meta_data.uid.clone();
        let header = Header::<AbeCrypto<A>, S>::generate(
            &engine,
            &public_key,
            Some(&EncryptionParameters {
                policy,
                policy_attributes: attributes,
            }),
            meta_data,
        )?;
        let symmetric_key = header.symmetric_key().to_owned();
        let header_bytes = header.as_bytes()?;
        Ok(HybridCipher {
            symmetric_key,
            header_bytes,
            uid,
            phantom: PhantomData,
        })
    }

    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }

    pub fn encrypt_block<const MAX_CLEAR_TEXT_SIZE: usize>(
        &self,
        input: &[u8],
        block_number: usize,
    ) -> anyhow::Result<Vec<u8>> {
        if input.len() > MAX_CLEAR_TEXT_SIZE {
            anyhow::bail!(
                "Too much data to encrypt: {}. The max clear text size is: {}",
                input.len(),
                MAX_CLEAR_TEXT_SIZE
            );
        }
        let symmetric_crypto = S::new();
        let mut b = Block::<S, MAX_CLEAR_TEXT_SIZE>::new();
        b.write(0, input)?;

        b.to_encrypted_bytes(
            &symmetric_crypto,
            &self.symmetric_key,
            &self.uid,
            block_number,
        )
        .map_err(Into::into)
    }
}

// impl<A, S> Debug for HybridCipher<A, S>
// where
//     A: AbeScheme + std::marker::Sync + std::marker::Send,
//     S: SymmetricCrypto,
// {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("HybridCipher")
//             .field("symmetric_key", self.symmetric_key.to_string())
//             .field("header_bytes", self.header_bytes.len())
//             .field("uid", self.uid.len())
//             // .field("phantom", &self.phantom)
//             .finish()
//     }
// }

impl<A, S> Drop for HybridCipher<A, S>
where
    A: AbeScheme + std::marker::Sync + std::marker::Send,
    S: SymmetricCrypto,
{
    fn drop(&mut self) {
        println!("Hybrid Cipher Dropped");
    }
}
