//! STARK of the 14 chrono C' map hashes (9 `node_digest` + 5 prio) of the
//! two-place [`HeightStatement`] height. Not `F`. Not matching. Does not
//! unlock settlement.

use commitments::public_statement_id;
use proof_plonky3::{decode_height_pi, verify_height_openings_with, FriClass, HEIGHT_OPENINGS};
use protocol_types::HeightStatement;

use crate::VerifyError;

/// Light-client-shaped [`crate::VerifyPi`] of those 13 hashes.
///
/// Envelope is `public_statement_id` || preimages || STARK. Public inputs
/// of the STARK are the last (prio) digest, not `post_root`. Successful
/// verify is **not** a CLOB apply license (`UNLOCKS_SETTLEMENT = false`).
pub struct HeightOpeningsVerifier {
    class: FriClass,
}

impl HeightOpeningsVerifier {
    /// p3-uni-stark test FRI (2 queries). Not a soundness claim.
    pub fn test() -> Self {
        Self {
            class: FriClass::Test,
        }
    }

    /// 100 queries, 16 PoW bits, official Poseidon2-16. Still not `F`.
    pub fn prod() -> Self {
        Self {
            class: FriClass::Prod,
        }
    }
}

impl crate::VerifyPi for HeightOpeningsVerifier {
    const UNLOCKS_SETTLEMENT: bool = false;

    fn verify(&self, statement: &HeightStatement, proof: &[u8]) -> Result<(), VerifyError> {
        let (sid, preimages, stark) = decode_height_pi(proof).ok_or(VerifyError)?;
        if sid != public_statement_id(statement).0 {
            return Err(VerifyError);
        }
        if preimages.len() != HEIGHT_OPENINGS {
            return Err(VerifyError);
        }
        verify_height_openings_with(preimages, &stark, self.class).map_err(|_| VerifyError)
    }
}
