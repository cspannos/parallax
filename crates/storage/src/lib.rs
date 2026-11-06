//! Encrypted append-only write-ahead log.
//!
//! This is durability for a single replica. It is not consensus, not a
//! disclosure capability, and not a keyed state store (see ADR 0007).
#![forbid(unsafe_code)]

mod wal;

pub use wal::{EncryptedWal, Replay, SyncMode, WalError, MAGIC, WAL_VERSION};
