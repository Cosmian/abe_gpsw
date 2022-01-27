use std::{fmt::Display, vec::Vec};

use crate::{
    core::gpsw::{AbeScheme, AsBytes},
    error::FormatErr,
};

#[derive(Debug)]
pub struct MasterPrivateKey<T: AbeScheme + Clone + PartialEq> {
    pub master_private_key: <T as AbeScheme>::MasterPrivateKey,
}

impl<T: AbeScheme + Clone + PartialEq> AsBytes for MasterPrivateKey<T> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        self.master_private_key
            .as_bytes()
            .map_err(|_e| FormatErr::ConversionFailed)
    }

    fn len_bytes(&self) -> usize {
        match self.as_bytes() {
            Ok(bytes) => bytes.len(),
            Err(_e) => 0,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let master_private_key = T::MasterPrivateKey::from_bytes(bytes)
            .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        Ok(MasterPrivateKey { master_private_key })
    }
}

#[derive(Debug)]
pub struct MasterKey<T: AbeScheme + Clone + PartialEq> {
    pub master_private_key: <T as AbeScheme>::MasterPrivateKey,
    pub master_public_key: <T as AbeScheme>::MasterPublicKey,
    pub master_public_delegation_key: <T as AbeScheme>::MasterPublicDelegationKey,
}

impl<T: AbeScheme + Clone + PartialEq> Display for MasterKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let (Ok(master_private_key), Ok(master_public_key), Ok(master_public_delegation_key)) = (
            self.master_private_key.as_bytes(),
            self.master_public_key.as_bytes(),
            self.master_public_delegation_key.as_bytes(),
        ) {
            write!(
                f,
                "{}{}{}",
                hex::encode(master_private_key),
                hex::encode(master_public_key),
                hex::encode(master_public_delegation_key)
            )
        } else {
            write!(f, "Invalid data")
        }
    }
}

impl<T: AbeScheme + Clone + PartialEq> MasterKey<T> {
    pub fn new(nb_attributes: usize) -> anyhow::Result<Self> {
        let (master_private_key, master_public_key, master_public_delegation_key) =
            T::default().generate_master_key(nb_attributes)?;
        Ok(Self {
            master_private_key,
            master_public_key,
            master_public_delegation_key,
        })
    }
}

impl<T: AbeScheme + Clone + PartialEq> PartialEq for MasterKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.master_private_key == other.master_private_key
            && self.master_public_key == other.master_public_key
            && self.master_public_delegation_key == other.master_public_delegation_key
    }
}

impl<T: AbeScheme + Clone + PartialEq> AsBytes for MasterKey<T> {
    fn as_bytes(&self) -> Result<Vec<u8>, FormatErr> {
        let mut bytes = self.master_private_key.as_bytes()?;
        bytes.extend(
            self.master_public_key
                .as_bytes()
                .map_err(|_e| FormatErr::ConversionFailed)?,
        );
        bytes.extend(
            self.master_public_delegation_key
                .as_bytes()
                .map_err(|_e| FormatErr::ConversionFailed)?,
        );
        Ok(bytes)
    }

    fn len_bytes(&self) -> usize {
        let bytes = self.as_bytes();
        match bytes {
            Ok(bytes) => bytes.len(),
            Err(_e) => 0,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FormatErr> {
        let master_private_key = T::MasterPrivateKey::from_bytes(bytes)
            .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        let master_public_key =
            T::MasterPublicKey::from_bytes(&bytes[master_private_key.len_bytes()..])
                .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        let master_public_delegation_key = T::MasterPublicDelegationKey::from_bytes(
            &bytes[master_private_key.len_bytes() + master_public_key.len_bytes()..],
        )
        .map_err(|e| FormatErr::Deserialization(e.to_string()))?;
        Ok(MasterKey {
            master_private_key,
            master_public_key,
            master_public_delegation_key,
        })
    }
}
