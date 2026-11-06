//! Rest qty/price are bound to the 216 B leaf. Take qty/price are bound to `I`.
//! Last digest is `post_root` (post INC). Genesis INC hashes to `pre_root`.
//! Parent is `GENESIS_PARENT`. Chrono map: nonce/seen roots equal openings
//! 9/13; resting map is empty. Rotate fixture (take `from_u128(5)`): seen
//! edge `13←12` (demoted left), demote pins `1≡8`/`3≡12`, left-overwrite
//! `7→9`/`11→13`. Heap+BST on `9←8` / `13←12`. Insert: Place1/2 order prios →
//! seen/rest/`I` ids; owner prios → nonce/`I` owners; resting order prio →
//! sell id; rest leaf owner → sell owner. Openings **19**. Not `F`. Does not
//! unlock settlement.

use commitments::public_statement_id;
use proof_plonky3::{
    blake3_hash_msg, decode_height_match_pi, encode_height_match_pi, prove_height_match_mid,
    verify_height_match_mid, FriClass, HEIGHT_MATCH_OPENINGS, INC_HEIGHT_OFF, INC_ROOT_BYTES,
    INPUT_COMMIT_BYTES, SETTLEMENT_COMMIT_BYTES,
};
use protocol_types::{ConsensusValue, HeightStatement};

use crate::apply_witness::ApplyWitness;
use crate::VerifyError;

/// HeightMatch envelope from a FULL_VIEW [`ApplyWitness`] tape.
///
/// Feeds `mid_books_root` as the mid-apply books public (AIR = resting leaf
/// digest). Does not re-run `F` — pair with [`crate::check_apply_witness`].
/// Still not `F`. Still `UNLOCKS_SETTLEMENT = false`. **19 ≠ 72 / 281 / 363497.**
pub fn height_match_pi_from_apply(
    witness: &ApplyWitness,
    class: FriClass,
) -> Result<Vec<u8>, VerifyError> {
    if witness.openings.len() != HEIGHT_MATCH_OPENINGS {
        return Err(VerifyError);
    }
    if witness.match_step.check().is_err() {
        return Err(VerifyError);
    }
    let proof = prove_height_match_mid(
        witness.openings.clone(),
        witness.match_step,
        witness.mid_books_root.0,
        class,
    )
    .map_err(|_| VerifyError)?;
    Ok(encode_height_match_pi(
        public_statement_id(&witness.statement).0,
        &witness.openings,
        &witness.match_step,
        &proof,
    ))
}

/// Light-client-shaped [`crate::VerifyPi`] of hashes + `I` + INC `C'` + match-step.
///
/// Envelope is `public_statement_id` || preimages || match-step || STARK.
/// Last preimage hashes to `statement.post_root`. The other 244 B preimage
/// hashes to `statement.pre_root`. The 233 B preimage hashes to
/// `statement.input_commitment`. The 277 B preimage hashes to
/// `statement.settlement_commitment`. `statement.height` equals the post INC
/// height payload. `statement.parent` is `GENESIS_PARENT`. Rest/take, INC
/// header, genesis `C`, and map roots bound as in the AIR. Settlement base
/// amounts equal fill; quote amounts equal notional. Maker account equals
/// the rest leaf owner and the first Place in `I`; taker equals the take
/// Place. First Place qty/price equal match rest. First Place
/// id/instrument/side equal the rest leaf. Take Place id/instrument
/// are `from_u128(5)` / instrument 1. First Place expiry/nonce equal the
/// rest leaf. Take Place expiry/nonce equal the same constants. Rest
/// `TimeSeq` is `TimeSeq(0)`, not post `next_time`. Rest left/right children
/// are `treap_empty_digest()`. Domain / version / key_len / OrderId key /
/// value_len / `RESTING` tag are the 216 B header. Seen/nonce share
/// `TREAP_NODE_DOMAIN` / version / lens; prio share `TREAP_PRIO_DOMAIN`.
/// First key byte is 1 or 2 by `hidx`. `I` is `INPUT_DOMAIN` / version /
/// payload_len 206 / count 2 / two `INPLACE`+`ORDER` tags. Both 244 B INC
/// openings are `INC_DOMAIN` / version / `height`. Settlement is
/// `RECEIPT_DOMAIN` / version / payload_len 248 / count 4 / four `DELTA`
/// tags. Post INC map tags are `nonces` / `seenid` / `books` with Digest
/// len 32. Seen left and nonce right children are `treap_empty_digest()`;
/// nonce root left equals opening 4 `out`; seen root left equals opening 7
/// `out`. Successful verify
/// is **not** a CLOB apply license (`UNLOCKS_SETTLEMENT = false`).
pub struct HeightMatchVerifier {
    class: FriClass,
}

impl HeightMatchVerifier {
    pub fn test() -> Self {
        Self {
            class: FriClass::Test,
        }
    }

    pub fn prod() -> Self {
        Self {
            class: FriClass::Prod,
        }
    }
}

impl crate::VerifyPi for HeightMatchVerifier {
    const UNLOCKS_SETTLEMENT: bool = false;

    fn verify(&self, statement: &HeightStatement, proof: &[u8]) -> Result<(), VerifyError> {
        let (sid, preimages, match_stmt, stark) =
            decode_height_match_pi(proof).ok_or(VerifyError)?;
        if sid != public_statement_id(statement).0 {
            return Err(VerifyError);
        }
        if preimages.len() != HEIGHT_MATCH_OPENINGS {
            return Err(VerifyError);
        }
        if statement.parent != ConsensusValue::GENESIS_PARENT {
            return Err(VerifyError);
        }
        let last = preimages.last().ok_or(VerifyError)?;
        if last.len() != INC_ROOT_BYTES {
            return Err(VerifyError);
        }
        if last[INC_HEIGHT_OFF..INC_HEIGHT_OFF + 8] != statement.height.0.to_le_bytes() {
            return Err(VerifyError);
        }
        if blake3_hash_msg(last) != statement.post_root.0 {
            return Err(VerifyError);
        }
        let incs: Vec<&Vec<u8>> = preimages
            .iter()
            .filter(|p| p.len() == INC_ROOT_BYTES)
            .collect();
        if incs.len() != 3 {
            return Err(VerifyError);
        }
        if blake3_hash_msg(incs[0]) != statement.pre_root.0 {
            return Err(VerifyError);
        }
        // incs[1] = mid INC (Place1); books = resting leaf digest.
        let mid = proof_plonky3::mid_books_from_openings(&preimages).ok_or(VerifyError)?;
        if incs[1][proof_plonky3::REST_ROOT_OFF..proof_plonky3::REST_ROOT_OFF + 32] != mid {
            return Err(VerifyError);
        }
        if incs[2].as_slice() != last.as_slice() {
            return Err(VerifyError);
        }
        let i = preimages
            .iter()
            .find(|p| p.len() == INPUT_COMMIT_BYTES)
            .ok_or(VerifyError)?;
        if blake3_hash_msg(i) != statement.input_commitment.0 {
            return Err(VerifyError);
        }
        let sett: Vec<&Vec<u8>> = preimages
            .iter()
            .filter(|p| p.len() == SETTLEMENT_COMMIT_BYTES)
            .collect();
        if sett.len() != 1 {
            return Err(VerifyError);
        }
        if blake3_hash_msg(sett[0]) != statement.settlement_commitment.0 {
            return Err(VerifyError);
        }
        verify_height_match_mid(preimages, match_stmt, mid, &stark, self.class)
            .map_err(|_| VerifyError)
    }
}
