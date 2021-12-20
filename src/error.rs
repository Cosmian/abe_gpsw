use std::{
    array::TryFromSliceError,
    convert::From,
    num::{ParseIntError, TryFromIntError},
};

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum FormatErr {
    #[error("attribute not found")]
    AttributeNotFound,
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
    #[error("attribute capacity overflow")]
    CapacityOverflow,
    #[error("attribute {0} for {1} already exists")]
    ExistingAttribute(String, String),
    #[error("policy {0} already exists")]
    ExistingPolicy(String),
    #[error("invalid size")]
    InvalidSize(String),
    #[error("{0}")]
    Deserialization(String),
    #[error("{0}")]
    InternalOperation(String),
    #[error("invalid formula: {0}")]
    InvalidFormula(String),
    #[error("conversion failed")]
    ConversionFailed,
    #[error("error parsing formula")]
    ParsingError(ParsingError),
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