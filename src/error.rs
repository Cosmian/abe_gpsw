use std::{
    array::TryFromSliceError,
    convert::{From, Infallible},
    ffi::NulError,
    num::{ParseIntError, TryFromIntError},
    str::Utf8Error,
};

#[cfg(feature = "interfaces")]
use cosmian_crypto_base::Error as CryptoError;
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum FormatErr {
    //
    // External errors conversion
    #[error("{0}")]
    CryptoError(String),
    #[error(transparent)]
    Infallible(Infallible),
    #[error(transparent)]
    NulError(NulError),
    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),
    #[error(transparent)]
    ParsingError(#[from] ParsingError),
    #[error(transparent)]
    FromHexError(#[from] FromHexError),
    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),

    //
    // Internal errors
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
    #[error("Empty private key")]
    EmptyPrivateKey,
    #[error("Empty ciphertext")]
    EmptyCiphertext,
    #[error("Empty plaintext")]
    EmptyPlaintext,
    #[error("Header length must be at least 4 bytes. Found {0}")]
    InvalidHeaderSize(usize),
}

impl From<TryFromSliceError> for FormatErr {
    fn from(_e: TryFromSliceError) -> Self {
        Self::ConversionFailed
    }
}

impl From<serde_json::Error> for FormatErr {
    fn from(e: serde_json::Error) -> Self {
        Self::Deserialization(e.to_string())
    }
}

#[cfg(feature = "interfaces")]
impl From<cosmian_crypto_base::Error> for FormatErr {
    fn from(e: cosmian_crypto_base::Error) -> Self {
        match e {
            CryptoError::SizeError { given, expected } => {
                Self::InvalidSize(format!("expected: {}, given: {}", expected, given))
            }
            CryptoError::InvalidSize(e) => Self::InvalidSize(e),
            e => Self::CryptoError(e.to_string()),
        }
    }
}

impl From<Infallible> for FormatErr {
    fn from(e: Infallible) -> Self {
        Self::Infallible(e)
    }
}

#[cfg(feature = "ffi")]
impl From<std::ffi::NulError> for FormatErr {
    fn from(e: std::ffi::NulError) -> Self {
        Self::NulError(e)
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
    #[error(transparent)]
    RegexError(#[from] regex::Error),
    #[error(transparent)]
    ParseIntError(#[from] ParseIntError),
    #[error("unsupported operand {0}")]
    UnsupportedOperand(String),
    #[error("unsupported operator {0}")]
    UnsupportedOperator(String),
}
