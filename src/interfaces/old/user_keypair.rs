use std::{
    convert::TryFrom,
    fmt::Display,
    io::{Error, ErrorKind},
    vec::Vec,
};

use cosmian_crypto_base::asymmetric::KeyPair;

use crate::{
    core::gpsw::{AbeScheme, AsBytes},
    error::FormatErr,
};

pub type UserDecryptionKey<T> = <T as AbeScheme>::UserDecryptionKey;

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey<T: AbeScheme + PartialEq + Clone>(pub T::MasterPublicKey);

impl<T: AbeScheme + Clone + PartialEq> TryFrom<&[u8]> for PublicKey<T> {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(PublicKey(T::MasterPublicKey::from_bytes(value).map_err(
            |e| Error::new(ErrorKind::InvalidInput, format!("{}", e)),
        )?))
    }
}

impl<T: AbeScheme + Clone + PartialEq> Display for PublicKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(bytes) = self.0.as_bytes() {
            write!(f, "{}", hex::encode(bytes))
        } else {
            write!(f, "Invalid input")
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserKeyPair<T: AbeScheme + Clone + PartialEq>
where
    UserDecryptionKey<T>: PartialEq + Clone,
    PublicKey<T>: PartialEq + Clone,
{
    private_key: UserDecryptionKey<T>,
    public_key: PublicKey<T>,
}

impl<T: AbeScheme + Clone + PartialEq> KeyPair for UserKeyPair<T>
where
    UserKeyPair<T>: PartialEq + Clone,
    UserDecryptionKey<T>: PartialEq + Clone,
    PublicKey<T>: PartialEq + Clone,
{
    type PrivateKey = UserDecryptionKey<T>;
    type PublicKey = PublicKey<T>;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn private_key(&self) -> &Self::PrivateKey {
        &self.private_key
    }
}

impl<T: AbeScheme + Clone + PartialEq> TryFrom<&[u8]> for UserKeyPair<T>
where
    UserKeyPair<T>: PartialEq + Clone,
    UserDecryptionKey<T>: PartialEq + Clone,
    PublicKey<T>: PartialEq + Clone,
{
    type Error = std::io::Error;

    // this impl is based on `Display` impl below (keys are concatenated)
    // please keep the same order !
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let public_key = T::MasterPublicKey::from_bytes(value)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{}", e)))?;
        let private_key = UserDecryptionKey::<T>::from_bytes(&value[public_key.len_bytes()..])
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{}", e)))?;
        Ok(UserKeyPair {
            private_key,
            public_key: PublicKey(public_key),
        })
    }
}

impl<T: AbeScheme + Clone + PartialEq> AsBytes for UserKeyPair<T>
where
    UserKeyPair<T>: PartialEq + Clone,
    UserDecryptionKey<T>: PartialEq + Clone,
    PublicKey<T>: PartialEq + Clone,
{
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut bytes = self
            .public_key()
            .0
            .as_bytes()
            .map_err(|_e| FormatErr::ConversionFailed)?;
        bytes.extend(
            self.private_key()
                .as_bytes()
                .map_err(|_e| FormatErr::ConversionFailed)?,
        );
        Ok(bytes)
    }

    fn len_bytes(&self) -> usize {
        match self.as_bytes() {
            Ok(bytes) => bytes.len(),
            Err(_e) => 0,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let public_key = T::MasterPublicKey::from_bytes(bytes)
            .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        let private_key = UserDecryptionKey::<T>::from_bytes(&bytes[public_key.len_bytes()..])
            .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        Ok(UserKeyPair {
            private_key,
            public_key: PublicKey(public_key),
        })
    }
}

impl<T: AbeScheme + Clone + PartialEq> Display for UserKeyPair<T>
where
    UserKeyPair<T>: PartialEq + Clone,
    UserDecryptionKey<T>: PartialEq + Clone,
    PublicKey<T>: PartialEq + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let (Ok(public_key), Ok(private_key)) =
            (self.public_key.0.as_bytes(), self.private_key.as_bytes())
        {
            write!(f, "{}{}", hex::encode(public_key), hex::encode(private_key))
        } else {
            write!(f, "Invalid data")
        }
    }
}
