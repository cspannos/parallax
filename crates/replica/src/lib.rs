//! Replica: durable `F` on one node.
//!
//! Four of these, given the same ordered `I`, must agree. That is a
//! determinism harness, not BFT (see ADR 0007).
#![forbid(unsafe_code)]

mod hexutil;
mod replica;

pub use hexutil::{decode_hex, encode_hex, HexError};
pub use replica::{OpenInfo, Replica, ReplicaError, ReplicaOpts};
pub use storage::SyncMode;
