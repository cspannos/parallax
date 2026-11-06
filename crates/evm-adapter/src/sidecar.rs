//! Engine API **shape** for settlement. Not Malachite `Value`. Not ExEx.

use protocol_types::{AssetId, Bytes32, OwnerId, SettlementDelta};

use crate::ledger::{Ledger, LedgerError};

#[derive(Clone, Debug)]
pub struct SettlementPayload {
    pub parent_evm_root: Bytes32,
    pub deltas: Vec<SettlementDelta>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadStatus {
    Valid {
        latest_valid_hash: Bytes32,
    },
    Invalid {
        validation_error: &'static str,
    },
    /// After Malachite decide this is an error (ADR 0004 / Arc discipline).
    Syncing,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SidecarError {
    #[error("unexpected SYNCING after decide")]
    UnexpectedSyncing,
    #[error("parent evm root mismatch")]
    ParentMismatch,
    #[error("unknown forkchoice head")]
    UnknownHead,
    #[error("{0}")]
    Ledger(#[from] LedgerError),
}

/// In-process settlement EL. A Reth process would implement the same methods
/// over JWT/IPC.
pub struct InProcessSidecar {
    ledger: Ledger,
    head: Bytes32,
    syncing: bool,
    payloads: u64,
}

impl InProcessSidecar {
    pub fn new(ledger: Ledger) -> Self {
        let head = ledger.state_root();
        Self {
            ledger,
            head,
            syncing: false,
            payloads: 0,
        }
    }

    pub fn set_syncing(&mut self, syncing: bool) {
        self.syncing = syncing;
    }

    pub fn payload_count(&self) -> u64 {
        self.payloads
    }

    pub fn head(&self) -> Bytes32 {
        self.head
    }

    pub fn new_payload(
        &mut self,
        payload: SettlementPayload,
    ) -> Result<PayloadStatus, SidecarError> {
        if self.syncing {
            return Ok(PayloadStatus::Syncing);
        }
        if payload.parent_evm_root != self.head {
            return Ok(PayloadStatus::Invalid {
                validation_error: "parent mismatch",
            });
        }
        match self.ledger.apply_batch(&payload.deltas) {
            Ok(()) => {
                self.payloads += 1;
                self.head = self.ledger.state_root();
                Ok(PayloadStatus::Valid {
                    latest_valid_hash: self.head,
                })
            }
            Err(LedgerError::InsufficientBalance) => Ok(PayloadStatus::Invalid {
                validation_error: "insufficient balance",
            }),
            Err(LedgerError::Overflow) => Ok(PayloadStatus::Invalid {
                validation_error: "overflow",
            }),
        }
    }

    pub fn forkchoice_updated(&mut self, head: Bytes32) -> Result<(), SidecarError> {
        if self.syncing {
            return Err(SidecarError::UnexpectedSyncing);
        }
        if head != self.head {
            return Err(SidecarError::UnknownHead);
        }
        Ok(())
    }

    /// Public balance query. Settlement-token analog of `eth_getBalance`.
    pub fn eth_get_balance(&self, account: OwnerId, asset: AssetId) -> u128 {
        self.ledger.balance(account, asset)
    }
}
