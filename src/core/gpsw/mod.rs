pub(crate) mod scheme;
use std::convert::{TryFrom, TryInto};

pub use scheme::Gpsw;

use crate::{core::msp::MonotoneSpanProgram, error::FormatErr};

pub trait AsBytes: Sized {
    fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr>;
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FormatErr>;
    fn len_bytes(&self) -> usize;
}

impl AsBytes for u32 {
    fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        if bytes.len() < 4 {
            return Err(FormatErr::Deserialization(
                "cannot deserialize u32 element since input bytes size is less than 4 bytes"
                    .to_string(),
            ));
        }
        Ok(Self::from_be_bytes(bytes[0..4].try_into()?))
    }

    fn len_bytes(&self) -> usize {
        4
    }
}

impl AsBytes for i32 {
    fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        Ok(Self::from_be_bytes(bytes[0..4].try_into()?))
    }

    fn len_bytes(&self) -> usize {
        4
    }
}

impl<T: AsBytes> AsBytes for Vec<T> {
    fn try_into_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        if self.is_empty() {
            return Ok(Vec::new());
        }
        // nb element in vector
        let mut bytes = Vec::new();
        let len = u32::try_from(self.len())?.to_be_bytes();
        bytes.extend_from_slice(&len);
        for val in self.iter() {
            bytes.append(&mut val.try_into_bytes()?)
        }
        Ok(bytes)
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        if bytes.is_empty() {
            return Ok(Self::new());
        }
        // retrieve len of vector
        let len: [u8; 4] = bytes[0..4].try_into()?;
        let len = u32::from_be_bytes(len) as usize;
        if len >= u32::MAX as usize {
            return Err(FormatErr::Deserialization(
                "deserializing element failed. Data altered?".to_string(),
            ));
        }
        let mut res = Self::with_capacity(len);
        res.push(T::try_from_bytes(&bytes[4..])?);
        // deserialize
        for i in 1..len {
            let beg = i * res[0].len_bytes();
            res.push(T::try_from_bytes(&bytes[4 + beg..])?)
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
    ) -> Result<
        (
            Self::MasterPrivateKey,
            Self::MasterPublicKey,
            Self::MasterPublicDelegationKey,
        ),
        FormatErr,
    >;

    fn key_generation(
        &self,
        msp: &MonotoneSpanProgram<i32>,
        priv_key: &Self::MasterPrivateKey,
    ) -> Result<Self::UserDecryptionKey, FormatErr>;

    fn key_delegation(
        &self,
        msp: &Option<MonotoneSpanProgram<i32>>,
        user_key: &Self::UserDecryptionKey,
        del_key: &Self::MasterPublicDelegationKey,
    ) -> Result<Self::UserDecryptionKey, FormatErr>;

    /// Generate a Random Plaintext as a point on GT
    fn generate_random_plaintext(&self) -> Result<Self::PlainText, FormatErr>;

    fn msg_encode(&self, msg: &[u8]) -> Result<Self::PlainText, FormatErr>;

    fn encrypt(
        &self,
        msg: &Self::PlainText,
        attr: &[u32],
        pub_key: &Self::MasterPublicKey,
    ) -> Result<Self::CipherText, FormatErr>;

    fn decrypt(
        &self,
        enc: &Self::CipherText,
        key: &Self::UserDecryptionKey,
    ) -> Result<Option<Self::PlainText>, FormatErr>;

    fn ciphertext_len(nb_attr: usize) -> usize;
}
