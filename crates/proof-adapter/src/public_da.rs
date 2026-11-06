//! Public-tier availability of [`HeightStatement`] (ADR 0005 / Q-DA-6).
//!
//! Validator replication of the public blob, not DAS, not a DA chain.
//! [`ConsensusValue`] is not enough: it does not carry `C` (`pre_root`).
//! This is not `π`.

use std::collections::BTreeMap;

use commitments::{public_statement_id, Digest};
use protocol_types::{ConsensusValue, Height, HeightStatement};

/// In-memory public DA store. One replica's copy of public statement bytes.
#[derive(Clone, Debug, Default)]
pub struct PublicStatementStore {
    blobs: BTreeMap<Height, HeightStatement>,
}

impl PublicStatementStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&mut self, stmt: HeightStatement) {
        self.blobs.insert(stmt.height, stmt);
    }

    pub fn get(&self, height: Height) -> Option<&HeightStatement> {
        self.blobs.get(&height)
    }

    pub fn digest(&self, height: Height) -> Option<Digest> {
        self.get(height).map(public_statement_id)
    }

    /// Light client can form the height instance. Not validity.
    pub fn available_for(&self, value: &ConsensusValue) -> bool {
        self.get(value.height)
            .is_some_and(|stmt| stmt.binds_value(value))
    }
}

/// Rejects every unlabeled height proof. Not Groth16. Not a fill STARK.
/// [`crate::HeightMatchVerifier`] is 14 C' map hashes + `I` + INC `C'` + match-step, not `F`.
pub struct NoHeightStark;

impl crate::VerifyPi for NoHeightStark {
    fn verify(
        &self,
        _statement: &HeightStatement,
        _proof: &[u8],
    ) -> Result<(), crate::VerifyError> {
        Err(crate::VerifyError)
    }
}
