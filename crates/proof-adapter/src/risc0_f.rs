//! `π` of `F` on RISC Zero (ADR 0025): the first [`VerifyPi`] that unlocks
//! settlement.
//!
//! The proof is a bincode [`Receipt`] of the `f_guest` image, which rebuilds
//! the engine from a canonical snapshot, commits its `C`, runs the real
//! matcher on `I`, and commits `mode ‖ pre_root ‖ post_root ‖
//! input_commitment ‖ settlement_commitment`. The verifier pins the image ID,
//! requires production rules (SHA-256 `C'`, ADR 0024; derived order ids, ADR
//! 0026: flag byte `0b11`), and requires the journal to
//! equal the statement's four `F` fields. `disable-dev-mode` means fake
//! receipts never verify.
//!
//! Trust: the RISC Zero proof system, and that `image_id` is the build of
//! the `clob` code the network runs. Not Groth16.

use clob::{F_CLAIM_BYTES, F_FLAGS_PRODUCTION};
use protocol_types::HeightStatement;
use risc0_zkvm::Receipt;

use crate::{VerifyError, VerifyPi};

/// Verifies `f_guest` receipts for one pinned image.
#[derive(Clone, Copy, Debug)]
pub struct Risc0FVerifier {
    pub image_id: [u32; 8],
}

impl VerifyPi for Risc0FVerifier {
    const UNLOCKS_SETTLEMENT: bool = true;

    fn verify(&self, statement: &HeightStatement, proof: &[u8]) -> Result<(), VerifyError> {
        let receipt: Receipt = bincode::deserialize(proof).map_err(|_| VerifyError)?;
        receipt.verify(self.image_id).map_err(|_| VerifyError)?;
        let j = &receipt.journal.bytes;
        if j.len() != F_CLAIM_BYTES || j[0] != F_FLAGS_PRODUCTION {
            return Err(VerifyError);
        }
        let fields = [
            &statement.pre_root.0,
            &statement.post_root.0,
            &statement.input_commitment.0,
            &statement.settlement_commitment.0,
        ];
        for (k, want) in fields.into_iter().enumerate() {
            if &j[1 + 32 * k..33 + 32 * k] != want.as_slice() {
                return Err(VerifyError);
            }
        }
        Ok(())
    }
}
