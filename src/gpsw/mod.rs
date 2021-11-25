pub mod abe;

use std::convert::{TryFrom, TryInto};

use crate::msp::MonotoneSpanProgram;

// Todo: Use Serde ?
pub trait AsBytes: Sized {
    fn as_bytes(&self) -> eyre::Result<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> eyre::Result<Self>;
    fn len_bytes(&self) -> usize;
}

impl AsBytes for u32 {
    fn as_bytes(&self) -> eyre::Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        eyre::ensure!(
            bytes.len() >= 4,
            "Cannot deserialize u32 element since input bytes size is less than 4 bytes"
        );
        Ok(u32::from_be_bytes(bytes[0..4].try_into()?))
    }

    fn len_bytes(&self) -> usize {
        4
    }
}

impl AsBytes for i32 {
    fn as_bytes(&self) -> eyre::Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        Ok(i32::from_be_bytes(bytes[0..4].try_into()?))
    }

    fn len_bytes(&self) -> usize {
        4
    }
}

impl<T: AsBytes> AsBytes for Vec<T> {
    fn as_bytes(&self) -> eyre::Result<Vec<u8>> {
        if self.is_empty() {
            return Ok(Vec::new())
        }
        // nb element in vector
        let mut bytes = Vec::new();
        let len = u32::try_from(self.len())?.to_be_bytes();
        bytes.extend_from_slice(&len);
        for val in self.iter() {
            bytes.append(&mut val.as_bytes()?)
        }
        Ok(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        if bytes.is_empty() {
            return Ok(Vec::new())
        }
        // retrieve len of vector
        let mut len = [0_u8; 4];
        len.copy_from_slice(&bytes[0..4]);
        let len = u32::from_be_bytes(len) as usize;
        eyre::ensure!(
            len < u32::MAX as usize,
            "Deserializing element failed. Data altered?"
        );
        let mut res = Vec::with_capacity(len);
        res.push(T::from_bytes(&bytes[4..])?);
        // deserialize
        for i in 1..len {
            let beg = i * res[0].len_bytes();
            res.push(T::from_bytes(&bytes[4 + beg..])?)
        }
        Ok(res)
    }

    fn len_bytes(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            4 + (self.len() * self[0].len_bytes())
        }
    }
}

pub trait AbeScheme: Default {
    type MasterPrivateKey: AsBytes + PartialEq + std::fmt::Debug;
    type MasterPublicKey: AsBytes + PartialEq + Clone + std::fmt::Debug;
    type MasterPublicDelegationKey: AsBytes + PartialEq + std::fmt::Debug;
    type UserDecryptionKey: AsBytes + PartialEq + Clone + std::fmt::Debug;
    type PlainText: AsBytes;
    type CipherText: AsBytes;

    fn description() -> String;

    fn generate_master_key(
        &self,
        size: usize,
    ) -> eyre::Result<(
        Self::MasterPrivateKey,
        Self::MasterPublicKey,
        Self::MasterPublicDelegationKey,
    )>;

    fn key_generation(
        &self,
        msp: &MonotoneSpanProgram<i32>,
        priv_key: &Self::MasterPrivateKey,
    ) -> eyre::Result<Self::UserDecryptionKey>;

    fn key_delegation(
        &self,
        msp: &Option<MonotoneSpanProgram<i32>>,
        user_key: &Self::UserDecryptionKey,
        del_key: &Self::MasterPublicDelegationKey,
    ) -> eyre::Result<Self::UserDecryptionKey>;

    /// Generate a Random Plaintext as a point on GT
    fn generate_random_plaintext(&self) -> eyre::Result<Self::PlainText>;

    fn msg_encode(&self, msg: &[u8]) -> eyre::Result<Self::PlainText>;

    fn encrypt(
        &self,
        msg: &Self::PlainText,
        attr: &[u32],
        pub_key: &Self::MasterPublicKey,
    ) -> eyre::Result<Self::CipherText>;

    fn decrypt(
        &self,
        enc: &Self::CipherText,
        key: &Self::UserDecryptionKey,
    ) -> eyre::Result<Option<Self::PlainText>>;

    fn ciphertext_len(nb_attr: usize) -> usize;
}
