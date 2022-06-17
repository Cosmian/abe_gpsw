use std::{
    array::TryFromSliceError,
    convert::{From, Infallible},
    ffi::NulError,
    num::{ParseIntError, TryFromIntError},
    str::Utf8Error,
};

use cosmian_crypto_base::Error as CryptoError;
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum FormatErr {
    #[error("{0}")]
    CryptoError(String),
    #[error("{0}")]
    FromHexError(FromHexError),
    #[error("{0}")]
    Infallible(Infallible),
    #[error("{0}")]
    Utf8Error(Utf8Error),
    #[error("{0}")]
    NulError(NulError),
    #[error("attribute not found: {0}")]
    AttributeNotFound(String),
    #[error("{} is missing{}",
        .item.clone().unwrap_or_else(|| "attribute".to_string()),
        match .axis_name {
            Some(axis) => format!(" in axis {}", axis),
            None => "".to_string(),
    })]
    MissingAttribute {
        item: Option<String>,
        axis_name: Option<String>,
    },
    #[error("{0} is missing")]
    MissingAxis(String),
    #[error("attribute {0} expected in {1:?}")]
    ExpectedAttribute(String, Vec<String>),
    #[error("unsupported operand {0}")]
    UnsupportedOperand(String),
    #[error("unsupported operator {0}")]
    UnsupportedOperator(String),
    #[error("symmetric key generation {0}")]
    SymmetricKeyGeneration(String),
    #[error("symmetric encryption {0}")]
    SymmetricEncryption(String),
    #[error("symmetric decryption {0}")]
    SymmetricDecryption(String),
    #[error("asymmetric decryption {0}")]
    AsymmetricDecryption(String),
    #[error("attribute capacity overflow")]
    CapacityOverflow,
    #[error("attribute {0} for {1} already exists")]
    ExistingAttribute(String, String),
    #[error("policy {0} already exists")]
    ExistingPolicy(String),
    #[error("invalid size")]
    InvalidSize(String),
    #[error("could not decode number of attributes in encrypted message")]
    DecodingAttributeNumber,
    #[error(
        "Unable to decrypt the header size. User decryption key has not the right policy to \
         decrypt this input."
    )]
    InsufficientAccessPolicy,
    #[error("{0}")]
    Deserialization(String),
    #[error("{0}")]
    Serialization(String),
    #[error("{0}")]
    InternalOperation(String),
    #[error("invalid formula: {0}")]
    InvalidFormula(String),
    #[error("invalid boolean expression: {0}")]
    InvalidBooleanExpression(String),
    #[error("invalid attribute: {0}")]
    InvalidAttribute(String),
    #[error("encrypted data size cannot be less than {0} bytes")]
    InvalidEncryptedDataSize(String),
    #[error("invalid encrypted data")]
    InvalidEncryptedData,
    #[error("conversion failed")]
    ConversionFailed,
    #[error("error parsing formula")]
    ParsingError(ParsingError),
    #[error("Empty private key")]
    EmptyPrivateKey,
    #[error("Empty ciphertext")]
    EmptyCiphertext,
    #[error("Empty plaintext")]
    EmptyPlaintext,
    #[error("Header length must be at least 4 bytes. Found {0}")]
    InvalidHeaderSize(usize),
}

impl From<TryFromIntError> for FormatErr {
    fn from(_e: TryFromIntError) -> Self {
        FormatErr::ConversionFailed
    }
}

impl From<TryFromSliceError> for FormatErr {
    fn from(_e: TryFromSliceError) -> Self {
        FormatErr::ConversionFailed
    }
}

impl From<ParseIntError> for FormatErr {
    fn from(_e: ParseIntError) -> Self {
        FormatErr::ConversionFailed
    }
}

impl From<regex::Error> for FormatErr {
    fn from(e: regex::Error) -> Self {
        ParsingError::RegexError(e).into()
    }
}

impl From<serde_json::Error> for FormatErr {
    fn from(e: serde_json::Error) -> Self {
        FormatErr::Deserialization(e.to_string())
    }
}

impl From<cosmian_crypto_base::Error> for FormatErr {
    fn from(e: cosmian_crypto_base::Error) -> Self {
        match e {
            CryptoError::SizeError { given, expected } => {
                FormatErr::InvalidSize(format!("expected: {}, given: {}", expected, given))
            }
            CryptoError::InvalidSize(e) => FormatErr::InvalidSize(e),
            e => FormatErr::CryptoError(e.to_string()),
        }
    }
}

impl From<FromHexError> for FormatErr {
    fn from(e: FromHexError) -> Self {
        FormatErr::FromHexError(e)
    }
}

impl From<Infallible> for FormatErr {
    fn from(e: Infallible) -> Self {
        FormatErr::Infallible(e)
    }
}

impl From<Utf8Error> for FormatErr {
    fn from(e: Utf8Error) -> Self {
        FormatErr::Utf8Error(e)
    }
}

#[cfg(feature = "ffi")]
impl From<std::ffi::NulError> for FormatErr {
    fn from(e: std::ffi::NulError) -> Self {
        FormatErr::NulError(e)
    }
}

impl From<anyhow::ErrReport> for FormatErr {
    fn from(e: anyhow::ErrReport) -> Self {
        FormatErr::CryptoError(e.to_string())
    }
}
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ParsingError {
    #[error("{0}")]
    UnexpectedCharacter(String),
    #[error("{0}")]
    UnexpectedEnd(String),
    #[error("empty string")]
    EmptyString,
    #[error("wrong range")]
    RangeError,
    #[error("{0}")]
    RegexError(#[from] regex::Error),
}

impl From<ParsingError> for FormatErr {
    fn from(pe: ParsingError) -> Self {
        FormatErr::ParsingError(pe)
    }
}
