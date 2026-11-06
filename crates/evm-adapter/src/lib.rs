//! M5 settlement sidecar: privileged `SettlementDelta` apply (ADR 0010).
//!
//! Engine API is an **adapter**, not the Malachite value. The CLOB is not an
//! ExEx. Apply is one batch per height, not per-order EVM txs. The apply log
//! is not the replica WAL.
#![forbid(unsafe_code)]

mod atomic;
mod ledger;
mod sidecar;

pub use atomic::{settlement_commitment, ApplyError, AtomicApply, SettledHeight};
pub use ledger::{Ledger, LedgerError};
pub use sidecar::{InProcessSidecar, PayloadStatus, SettlementPayload, SidecarError};
