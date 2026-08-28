//! ferry-deadman: timelocked succession for any git repository.
//!
//! Seal an archive of a repo so that it can only be decrypted after a future
//! drand beacon round. Heartbeats push the unlock forward; silence lets the
//! mathematics open it.
#![forbid(unsafe_code)]

pub mod archive;
pub mod artifact;
pub mod beacon;
pub mod commands;
pub mod config;
pub mod duration;
pub mod error;
pub mod fingerprint;
pub mod state;
pub mod tlock;

#[cfg(test)]
pub mod testsupport;

pub use error::{Error, Result};
