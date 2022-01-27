#![allow(clippy::type_complexity)]

pub mod error;

pub(crate) mod core;

#[cfg(feature = "interfaces")]
pub mod interfaces;
