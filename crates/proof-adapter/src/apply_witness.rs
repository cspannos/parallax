//! Named FULL_VIEW witness tying the HeightMatch opening tape to native `F`.
//!
//! Carries [`HeightStatement`] + `I` + the 19 openings + match-step + mid-apply
//! books root (after the rest Place). Openings include mid INC (Place1) between
//! genesis and settlement. Native check replays `F`, requires the openings
//! equal the traced apply, locksteps the fill to match-step, requires mid
//! books = 216 B resting leaf `out`, mid INC books/nonce/seen = Place1 map
//! roots, post books empty, and treap heap+BST on chrono edges `9←8` / `13←12`,
//! demote pins `1≡8`/`3≡12`, left-overwrite `7→9`/`11→13`, insert keys for
//! Place1+2 (order prios ↔ seen/rest/`I` ids; owner prios ↔ nonce/`I` owners;
//! resting order prio ↔ sell id; rest leaf owner ↔ sell owner).
//! HeightMatch AIR binds mid public + mid INC + heap + BST + demote out pins +
//! insert key latches. Not `π`. Does not unlock settlement.
//! **19 ≠ 72 / 281 / 363497.** Chronological map openings. Not full
//! rotate/insert algebra and not `F`.

use clob::{BTreeBook, Engine, TreapHash};
use commitments::{priority_u64, start_c_prime_trace, take_c_prime_trace, treap_empty_digest};
use consensus_adapter::{check_height_statement, height_statement, HeightStatementError};
use proof_plonky3::{
    blake3_hash_msg, input_commit_preimage, settlement_commit_preimage, HEIGHT_MATCH_OPENINGS,
    INC_HEIGHT_OFF, INC_NEXT_T_OFF, INC_ROOT_BYTES, INPUT_COMMIT_BYTES, NONCE_NODE_BYTES,
    NONCE_ROOT_OFF, RESTING_NODE_BYTES, REST_ROOT_OFF, SEEN_NODE_BYTES, SEEN_ROOT_OFF,
    SETTLEMENT_COMMIT_BYTES,
};
use protocol_types::{Bytes32, Height, HeightStatement, Input};
use tiny_f::MatchStepStatement;

/// First key byte offset inside seen/nonce/resting `node_digest` preimages.
const NODE_KEY_OFF: usize = 59;
const NONCE_KEY_LEN: usize = 32;
const SEEN_KEY_LEN: usize = 16;
const PRIO_KEY_OFF: usize = 17;
const PRIO_ORDER_BYTES: usize = 33;
const PRIO_OWNER_BYTES: usize = 49;
const INPUT_TAKE_ID_OFF: usize = 148;
const INPUT_TAKE_OWNER_OFF: usize = 185;
const INPUT_SELL_ID_OFF: usize = 47;
const INPUT_SELL_OWNER_OFF: usize = 84;
const RESTING_ID_OFF: usize = 91;
const RESTING_OWNER_OFF: usize = 128;
const HIDX_NONCE_FIRST: usize = 1;
const HIDX_ORDER_K1: usize = 2;
const HIDX_SEEN_FIRST: usize = 3;
const HIDX_ORDER_REST: usize = 4;
const HIDX_OWNER_K2: usize = 6;
const HIDX_NONCE_K2: usize = 7;
const HIDX_ORDER_K5: usize = 10;
const HIDX_SEEN_K5: usize = 11;
const HIDX_REST: usize = 5;
const HIDX_I: usize = 14;

/// FULL_VIEW witness that `statement` is `C' = F(C, I)` with the HeightMatch
/// opening tape. Not `π`. Successful check is **not** a CLOB apply license
/// (`UNLOCKS_SETTLEMENT` stays false on [`crate::HeightMatchVerifier`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyWitness {
    pub statement: HeightStatement,
    pub inputs: Vec<Input>,
    /// Trace order: 9 node + 5 prio + `I` + genesis INC + mid INC + settlement +
    /// post INC.
    pub openings: Vec<Vec<u8>>,
    pub match_step: MatchStepStatement,
    /// Books (resting) map root after the first Place alone. Equals the 216 B
    /// resting leaf digest. Not post-`F` books (those are empty on this fixture).
    pub mid_books_root: Bytes32,
    /// `incremental_root_preimage` after the first Place alone. Equals the mid
    /// INC opening (index 15). Books slice equals [`Self::mid_books_root`].
    pub mid_inc_preimage: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApplyWitnessError {
    #[error("HeightMatch is C' v1: the engine must use TreapHash::Blake3")]
    HashMode,
    #[error("native F does not produce this HeightStatement")]
    Statement(#[from] HeightStatementError),
    #[error("opening tape does not match traced apply")]
    Openings,
    #[error("match-step does not lockstep the fill")]
    MatchStep,
    #[error("mid-apply books root does not equal resting leaf")]
    MidBooks,
    #[error("mid INC after Place1 does not match map roots")]
    MidInc,
    #[error("treap heap or BST violated on parent/child edges")]
    TreapEdge,
    #[error("Place2 insert keys do not match I take id/owner")]
    InsertKey,
}

/// Trace `F` on a scratch engine; stack the HeightMatch openings.
pub fn build_apply_witness(
    engine: &Engine<BTreeBook>,
    parent: Bytes32,
    consensus_height: Height,
    inputs: &[Input],
    match_step: MatchStepStatement,
) -> ApplyWitness {
    assert_eq!(engine.treap_hash(), TreapHash::Blake3, "HeightMatch is C' v1 (BLAKE3)");
    let statement = height_statement(engine, parent, consensus_height, inputs);
    let (openings, _) = trace_openings(engine, inputs);
    let (mid_books_root, mid_inc_preimage) = mid_state_after_rest(engine, inputs);
    ApplyWitness {
        statement,
        inputs: inputs.to_vec(),
        openings,
        match_step,
        mid_books_root,
        mid_inc_preimage,
    }
}

/// Native: statement = `F`, openings = traced apply, match-step locksteps fill,
/// mid books = resting leaf, mid INC = Place1, post books empty, heap+BST on
/// chrono edges `9←8` / `13←12`.
pub fn check_apply_witness(
    engine: &Engine<BTreeBook>,
    parent: Bytes32,
    consensus_height: Height,
    witness: &ApplyWitness,
) -> Result<(), ApplyWitnessError> {
    if engine.treap_hash() != TreapHash::Blake3 {
        return Err(ApplyWitnessError::HashMode);
    }
    check_height_statement(
        engine,
        parent,
        consensus_height,
        &witness.inputs,
        &witness.statement,
    )?;
    if witness.openings.len() != HEIGHT_MATCH_OPENINGS {
        return Err(ApplyWitnessError::Openings);
    }
    let (expected, receipts) = trace_openings(engine, &witness.inputs);
    if witness.openings != expected {
        return Err(ApplyWitnessError::Openings);
    }
    if !openings_bind_statement(&witness.openings, &witness.statement) {
        return Err(ApplyWitnessError::Openings);
    }
    if witness.match_step.check().is_err() || !fill_lockstep(&receipts, &witness.match_step) {
        return Err(ApplyWitnessError::MatchStep);
    }
    check_mid_books(engine, witness)?;
    check_mid_inc(engine, witness)?;
    check_treap_edges(&witness.openings)?;
    check_insert_keys(&witness.openings)?;
    Ok(())
}

/// Place1+2 insert first-key bytes: order prios ↔ seen/rest/`I` ids; owner
/// prios ↔ nonce/`I` owners; resting order prio ↔ sell id; rest owner ↔ sell
/// owner. Locksteps HeightMatch AIR insert latches. Not full insert walk; not
/// `F`.
fn check_insert_keys(openings: &[Vec<u8>]) -> Result<(), ApplyWitnessError> {
    let prio_o2 = openings.get(HIDX_ORDER_K5).ok_or(ApplyWitnessError::InsertKey)?;
    let seen2 = openings.get(HIDX_SEEN_K5).ok_or(ApplyWitnessError::InsertKey)?;
    let prio_n2 = openings.get(HIDX_OWNER_K2).ok_or(ApplyWitnessError::InsertKey)?;
    let nonce2 = openings.get(HIDX_NONCE_K2).ok_or(ApplyWitnessError::InsertKey)?;
    let prio_o1 = openings.get(HIDX_ORDER_K1).ok_or(ApplyWitnessError::InsertKey)?;
    let prio_rest = openings.get(HIDX_ORDER_REST).ok_or(ApplyWitnessError::InsertKey)?;
    let seen1 = openings.get(HIDX_SEEN_FIRST).ok_or(ApplyWitnessError::InsertKey)?;
    let prio_n1 = openings.first().ok_or(ApplyWitnessError::InsertKey)?;
    let nonce1 = openings.get(HIDX_NONCE_FIRST).ok_or(ApplyWitnessError::InsertKey)?;
    let rest = openings.get(HIDX_REST).ok_or(ApplyWitnessError::InsertKey)?;
    let i = openings.get(HIDX_I).ok_or(ApplyWitnessError::InsertKey)?;
    if prio_o2.len() != PRIO_ORDER_BYTES
        || prio_o1.len() != PRIO_ORDER_BYTES
        || prio_rest.len() != PRIO_ORDER_BYTES
        || prio_n2.len() != PRIO_OWNER_BYTES
        || prio_n1.len() != PRIO_OWNER_BYTES
        || seen2.len() != SEEN_NODE_BYTES
        || seen1.len() != SEEN_NODE_BYTES
        || nonce2.len() != NONCE_NODE_BYTES
        || nonce1.len() != NONCE_NODE_BYTES
        || rest.len() != RESTING_NODE_BYTES
        || i.len() != INPUT_COMMIT_BYTES
    {
        return Err(ApplyWitnessError::InsertKey);
    }
    let tid = prio_o2[PRIO_KEY_OFF];
    let town = prio_n2[PRIO_KEY_OFF];
    let sid = prio_o1[PRIO_KEY_OFF];
    let sown = prio_n1[PRIO_KEY_OFF];
    if seen2[NODE_KEY_OFF] != tid
        || i[INPUT_TAKE_ID_OFF] != tid
        || nonce2[NODE_KEY_OFF] != town
        || i[INPUT_TAKE_OWNER_OFF] != town
        || seen1[NODE_KEY_OFF] != sid
        || i[INPUT_SELL_ID_OFF] != sid
        || rest[RESTING_ID_OFF] != sid
        || prio_rest[PRIO_KEY_OFF] != sid
        || nonce1[NODE_KEY_OFF] != sown
        || i[INPUT_SELL_OWNER_OFF] != sown
        || rest[RESTING_OWNER_OFF] != sown
    {
        return Err(ApplyWitnessError::InsertKey);
    }
    Ok(())
}

/// Heap + BST on chrono edges `9←8` / `13←12`, demote pins `1≡8` / `3≡12`, and
/// left-overwrite identity `7→9` / `11→13` (differ only in left `[19..51]`).
/// Matches HeightMatch AIR rotate fixture; not full rotate algebra; not `F`.
fn check_treap_edges(openings: &[Vec<u8>]) -> Result<(), ApplyWitnessError> {
    // Chronological map indices (lockstep HeightMatch HIDX_*).
    const NONCE_FIRST: usize = 1;
    const SEEN_FIRST: usize = 3;
    const NONCE_K2: usize = 7;
    const NONCE_PREV: usize = 8;
    const NONCE_ROOT: usize = 9;
    const SEEN_K5: usize = 11;
    const SEEN_DEMOT: usize = 12;
    const SEEN_ROOT: usize = 13;
    let n_nf = openings.get(NONCE_FIRST).ok_or(ApplyWitnessError::TreapEdge)?;
    let n_sf = openings.get(SEEN_FIRST).ok_or(ApplyWitnessError::TreapEdge)?;
    let n_nk = openings.get(NONCE_K2).ok_or(ApplyWitnessError::TreapEdge)?;
    let n_np = openings.get(NONCE_PREV).ok_or(ApplyWitnessError::TreapEdge)?;
    let n_nr = openings.get(NONCE_ROOT).ok_or(ApplyWitnessError::TreapEdge)?;
    let n_sk = openings.get(SEEN_K5).ok_or(ApplyWitnessError::TreapEdge)?;
    let n_sd = openings.get(SEEN_DEMOT).ok_or(ApplyWitnessError::TreapEdge)?;
    let n_sr = openings.get(SEEN_ROOT).ok_or(ApplyWitnessError::TreapEdge)?;
    if n_nf.len() != NONCE_NODE_BYTES
        || n_np.len() != NONCE_NODE_BYTES
        || n_nk.len() != NONCE_NODE_BYTES
        || n_nr.len() != NONCE_NODE_BYTES
        || n_sf.len() != SEEN_NODE_BYTES
        || n_sk.len() != SEEN_NODE_BYTES
        || n_sd.len() != SEEN_NODE_BYTES
        || n_sr.len() != SEEN_NODE_BYTES
    {
        return Err(ApplyWitnessError::TreapEdge);
    }
    // Demote / rehash pins (full preimage).
    if n_nf != n_np || n_sf != n_sd {
        return Err(ApplyWitnessError::TreapEdge);
    }
    // Left-overwrite: leaf→root identical outside left child bytes.
    const LEFT: usize = 19;
    const LEFT_END: usize = 51;
    if n_nk[..LEFT] != n_nr[..LEFT]
        || n_nk[LEFT_END..] != n_nr[LEFT_END..]
        || n_sk[..LEFT] != n_sr[..LEFT]
        || n_sk[LEFT_END..] != n_sr[LEFT_END..]
    {
        return Err(ApplyWitnessError::TreapEdge);
    }
    let k_np = &n_np[NODE_KEY_OFF..NODE_KEY_OFF + NONCE_KEY_LEN];
    let k_nr = &n_nr[NODE_KEY_OFF..NODE_KEY_OFF + NONCE_KEY_LEN];
    let k_sd = &n_sd[NODE_KEY_OFF..NODE_KEY_OFF + SEEN_KEY_LEN];
    let k_sr = &n_sr[NODE_KEY_OFF..NODE_KEY_OFF + SEEN_KEY_LEN];
    // BST: left child < parent on both edges.
    if k_np >= k_nr || k_sd >= k_sr {
        return Err(ApplyWitnessError::TreapEdge);
    }
    // Heap: parent prio > child prio.
    let p_np = priority_u64(k_np);
    let p_nr = priority_u64(k_nr);
    let p_sd = priority_u64(k_sd);
    let p_sr = priority_u64(k_sr);
    if !(p_nr > p_np) || !(p_sr > p_sd) {
        return Err(ApplyWitnessError::TreapEdge);
    }
    Ok(())
}

fn mid_state_after_rest(engine: &Engine<BTreeBook>, inputs: &[Input]) -> (Bytes32, Vec<u8>) {
    let Some(first) = inputs.first() else {
        return (
            Bytes32(treap_empty_digest().0),
            engine.incremental_root_preimage(),
        );
    };
    let mut mid = engine.clone();
    mid.set_treap_hash(TreapHash::Blake3Count);
    let _ = mid.apply_all(std::iter::once(first.clone()));
    debug_assert_eq!(mid.incremental_resting_len(), 1);
    (
        Bytes32(mid.incremental_map_roots().2 .0),
        mid.incremental_root_preimage(),
    )
}

fn check_mid_books(
    engine: &Engine<BTreeBook>,
    witness: &ApplyWitness,
) -> Result<(), ApplyWitnessError> {
    let (expected_mid, _) = mid_state_after_rest(engine, &witness.inputs);
    if witness.mid_books_root != expected_mid {
        return Err(ApplyWitnessError::MidBooks);
    }
    let Some(resting) = witness
        .openings
        .iter()
        .find(|p| p.len() == RESTING_NODE_BYTES)
    else {
        return Err(ApplyWitnessError::MidBooks);
    };
    if blake3_hash_msg(resting) != witness.mid_books_root.0 {
        return Err(ApplyWitnessError::MidBooks);
    }
    let mut post = engine.clone();
    post.set_treap_hash(TreapHash::Blake3Count);
    let _ = post.apply_all(witness.inputs.iter().cloned());
    if post.incremental_resting_len() != 0 {
        return Err(ApplyWitnessError::MidBooks);
    }
    if post.incremental_map_roots().2 != treap_empty_digest() {
        return Err(ApplyWitnessError::MidBooks);
    }
    if witness.mid_books_root.0 == treap_empty_digest().0 {
        return Err(ApplyWitnessError::MidBooks);
    }
    Ok(())
}

fn check_mid_inc(
    engine: &Engine<BTreeBook>,
    witness: &ApplyWitness,
) -> Result<(), ApplyWitnessError> {
    let (books, expected_inc) = mid_state_after_rest(engine, &witness.inputs);
    if witness.mid_inc_preimage != expected_inc {
        return Err(ApplyWitnessError::MidInc);
    }
    if witness.mid_inc_preimage.len() != INC_ROOT_BYTES {
        return Err(ApplyWitnessError::MidInc);
    }
    if witness.mid_inc_preimage[REST_ROOT_OFF..REST_ROOT_OFF + 32] != books.0 {
        return Err(ApplyWitnessError::MidInc);
    }
    if witness.mid_inc_preimage[REST_ROOT_OFF..REST_ROOT_OFF + 32] != witness.mid_books_root.0 {
        return Err(ApplyWitnessError::MidInc);
    }
    let mut mid = engine.clone();
    mid.set_treap_hash(TreapHash::Blake3Count);
    if let Some(first) = witness.inputs.first() {
        let _ = mid.apply_all(std::iter::once(first.clone()));
    }
    let (nonce_r, seen_r, rest_r) = mid.incremental_map_roots();
    if witness.mid_inc_preimage[NONCE_ROOT_OFF..NONCE_ROOT_OFF + 32] != nonce_r.0 {
        return Err(ApplyWitnessError::MidInc);
    }
    if witness.mid_inc_preimage[SEEN_ROOT_OFF..SEEN_ROOT_OFF + 32] != seen_r.0 {
        return Err(ApplyWitnessError::MidInc);
    }
    if witness.mid_inc_preimage[REST_ROOT_OFF..REST_ROOT_OFF + 32] != rest_r.0 {
        return Err(ApplyWitnessError::MidInc);
    }
    // Height / next_time: this fixture Place1 advances next_time to 1.
    let height = u64::from_le_bytes(
        witness.mid_inc_preimage[INC_HEIGHT_OFF..INC_HEIGHT_OFF + 8]
            .try_into()
            .map_err(|_| ApplyWitnessError::MidInc)?,
    );
    let next_t = u64::from_le_bytes(
        witness.mid_inc_preimage[INC_NEXT_T_OFF..INC_NEXT_T_OFF + 8]
            .try_into()
            .map_err(|_| ApplyWitnessError::MidInc)?,
    );
    if height != witness.statement.height.0 || next_t != 1 {
        return Err(ApplyWitnessError::MidInc);
    }
    let genesis = witness
        .openings
        .iter()
        .find(|p| p.len() == INC_ROOT_BYTES)
        .ok_or(ApplyWitnessError::MidInc)?;
    let post = witness.openings.last().ok_or(ApplyWitnessError::MidInc)?;
    if witness.mid_inc_preimage.as_slice() == genesis.as_slice()
        || witness.mid_inc_preimage.as_slice() == post.as_slice()
    {
        return Err(ApplyWitnessError::MidInc);
    }
    // Mid INC is opening 15 on the HeightMatch tape.
    let incs: Vec<&Vec<u8>> = witness
        .openings
        .iter()
        .filter(|p| p.len() == INC_ROOT_BYTES)
        .collect();
    if incs.len() != 3 || incs[1].as_slice() != witness.mid_inc_preimage.as_slice() {
        return Err(ApplyWitnessError::MidInc);
    }
    Ok(())
}

fn trace_openings(
    engine: &Engine<BTreeBook>,
    inputs: &[Input],
) -> (Vec<Vec<u8>>, Vec<clob::Receipt>) {
    let genesis_inc = engine.incremental_root_preimage();
    let (_, mid_inc) = mid_state_after_rest(engine, inputs);
    let mut scratch = engine.clone();
    scratch.set_treap_hash(TreapHash::Blake3Count);
    start_c_prime_trace();
    let receipts = scratch.apply_all(inputs.iter().cloned());
    let mut openings = take_c_prime_trace();
    let deltas: Vec<_> = receipts
        .iter()
        .flat_map(|r| r.settlement.iter().cloned())
        .collect();
    openings.push(input_commit_preimage(inputs));
    openings.push(genesis_inc);
    openings.push(mid_inc);
    openings.push(settlement_commit_preimage(&deltas));
    openings.push(scratch.incremental_root_preimage());
    (openings, receipts)
}

fn openings_bind_statement(openings: &[Vec<u8>], stmt: &HeightStatement) -> bool {
    let Some(last) = openings.last() else {
        return false;
    };
    if last.len() != INC_ROOT_BYTES || blake3_hash_msg(last) != stmt.post_root.0 {
        return false;
    }
    let incs: Vec<&Vec<u8>> = openings
        .iter()
        .filter(|p| p.len() == INC_ROOT_BYTES)
        .collect();
    if incs.len() != 3 || blake3_hash_msg(incs[0]) != stmt.pre_root.0 {
        return false;
    }
    if incs[2].as_slice() != last.as_slice() {
        return false;
    }
    let Some(i) = openings.iter().find(|p| p.len() == INPUT_COMMIT_BYTES) else {
        return false;
    };
    if blake3_hash_msg(i) != stmt.input_commitment.0 {
        return false;
    }
    let Some(s) = openings.iter().find(|p| p.len() == SETTLEMENT_COMMIT_BYTES) else {
        return false;
    };
    blake3_hash_msg(s) == stmt.settlement_commitment.0
}

fn fill_lockstep(receipts: &[clob::Receipt], match_step: &MatchStepStatement) -> bool {
    receipts
        .iter()
        .flat_map(|r| r.fills.iter())
        .any(|f| f.qty == match_step.output.fill_qty && f.price == match_step.output.fill_price)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine_v1, limit_v1};
    use protocol_types::{ConsensusValue, Price, Qty, Side};
    use tiny_f::{MatchStepInstance, MatchStepStatement};

    fn crossing_i() -> Vec<Input> {
        vec![
            Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit_v1(5, 2, Side::Buy, 10, 100, 1)),
        ]
    }

    fn crossing_match() -> MatchStepStatement {
        MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(10),
            take_price: Price(100),
        })
        .unwrap()
    }

    #[test]
    fn apply_witness_checks_native_f() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        assert_eq!(w.openings.len(), HEIGHT_MATCH_OPENINGS);
        let resting = w
            .openings
            .iter()
            .find(|p| p.len() == RESTING_NODE_BYTES)
            .unwrap();
        assert_eq!(blake3_hash_msg(resting), w.mid_books_root.0);
        assert_eq!(w.mid_inc_preimage.len(), INC_ROOT_BYTES);
        assert_eq!(
            &w.mid_inc_preimage[REST_ROOT_OFF..REST_ROOT_OFF + 32],
            &w.mid_books_root.0
        );
        check_apply_witness(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &w).unwrap();
    }

    #[test]
    fn wrong_i_rejected() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        w.inputs = vec![Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1))];
        assert!(matches!(
            check_apply_witness(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &w),
            Err(ApplyWitnessError::Statement(_))
        ));
    }

    #[test]
    fn wrong_post_rejected() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        w.statement.post_root = w.statement.pre_root;
        assert!(matches!(
            check_apply_witness(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &w),
            Err(ApplyWitnessError::Statement(_))
        ));
    }

    #[test]
    fn wrong_opening_rejected() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        w.openings[0][0] ^= 1;
        assert_eq!(
            check_apply_witness(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &w),
            Err(ApplyWitnessError::Openings)
        );
    }

    #[test]
    fn wrong_match_step_rejected() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        w.match_step = MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(5),
            take_price: Price(100),
        })
        .unwrap();
        assert_eq!(
            check_apply_witness(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &w),
            Err(ApplyWitnessError::MatchStep)
        );
    }

    #[test]
    fn wrong_mid_books_rejected() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        w.mid_books_root = Bytes32(treap_empty_digest().0);
        assert_eq!(
            check_apply_witness(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &w),
            Err(ApplyWitnessError::MidBooks)
        );
    }

    #[test]
    fn wrong_mid_inc_rejected() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        // Genesis INC is the wrong mid (empty books).
        w.mid_inc_preimage = engine.incremental_root_preimage();
        assert_eq!(
            check_apply_witness(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &w),
            Err(ApplyWitnessError::MidInc)
        );
    }

    #[test]
    fn mid_inc_is_not_genesis_or_post() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        let genesis = w
            .openings
            .iter()
            .find(|p| p.len() == INC_ROOT_BYTES)
            .unwrap();
        let post = w.openings.last().unwrap();
        assert_ne!(w.mid_inc_preimage.as_slice(), genesis.as_slice());
        assert_ne!(w.mid_inc_preimage.as_slice(), post.as_slice());
        assert_ne!(
            &w.mid_inc_preimage[REST_ROOT_OFF..REST_ROOT_OFF + 32],
            &treap_empty_digest().0
        );
        assert_eq!(
            &post[REST_ROOT_OFF..REST_ROOT_OFF + 32],
            &treap_empty_digest().0
        );
        // Mid nonce/seen outs appear among the chrono map openings (Place1 path).
        let nonce = &w.mid_inc_preimage[NONCE_ROOT_OFF..NONCE_ROOT_OFF + 32];
        let seen = &w.mid_inc_preimage[SEEN_ROOT_OFF..SEEN_ROOT_OFF + 32];
        let map_outs: Vec<_> = w.openings[..14]
            .iter()
            .map(|p| blake3_hash_msg(p))
            .collect();
        assert!(map_outs.iter().any(|o| o.as_slice() == nonce));
        assert!(map_outs.iter().any(|o| o.as_slice() == seen));
        assert_eq!(w.openings.len(), 19);
        assert_eq!(HEIGHT_MATCH_OPENINGS, 19);
        assert_eq!(w.openings[16], w.mid_inc_preimage);
    }

    #[test]
    fn mid_books_is_not_post_books() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        let mut post = engine.clone();
        post.apply_all(inputs.iter().cloned());
        assert_eq!(post.incremental_map_roots().2, treap_empty_digest());
        assert_ne!(w.mid_books_root.0, post.incremental_map_roots().2 .0);
        assert_eq!(w.openings.len(), HEIGHT_MATCH_OPENINGS);
    }

    #[test]
    fn openings_are_not_engine_insert_tape() {
        assert_eq!(HEIGHT_MATCH_OPENINGS, 19);
        assert_ne!(HEIGHT_MATCH_OPENINGS, 72);
        assert_ne!(HEIGHT_MATCH_OPENINGS, 281);
        assert_ne!(HEIGHT_MATCH_OPENINGS, 363497);
    }

    #[test]
    fn treap_edges_heap_and_bst() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        check_treap_edges(&w.openings).unwrap();
        assert!(check_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &w
        )
        .is_ok());
    }

    #[test]
    fn wrong_treap_edge_key_rejected() {
        let engine = btree_engine_v1();
        let inputs = crossing_i();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &inputs,
            crossing_match(),
        );
        // Corrupt child key on nonce edge 9←8 → breaks BST (and heap pairing).
        w.openings[8][NODE_KEY_OFF] = 9;
        assert_eq!(
            check_treap_edges(&w.openings),
            Err(ApplyWitnessError::TreapEdge)
        );
    }

    #[test]
    fn wrong_demote_pin_rejected() {
        let engine = btree_engine_v1();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &crossing_i(),
            crossing_match(),
        );
        w.openings[12][NODE_KEY_OFF + 1] ^= 1;
        assert_eq!(
            check_treap_edges(&w.openings),
            Err(ApplyWitnessError::TreapEdge)
        );
    }

    #[test]
    fn wrong_left_overwrite_rejected() {
        let engine = btree_engine_v1();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &crossing_i(),
            crossing_match(),
        );
        // Corrupt a byte after left on seen leaf 11 without touching root 13.
        w.openings[11][51] ^= 1;
        assert_eq!(
            check_treap_edges(&w.openings),
            Err(ApplyWitnessError::TreapEdge)
        );
    }

    #[test]
    fn wrong_insert_take_id_rejected() {
        let engine = btree_engine_v1();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &crossing_i(),
            crossing_match(),
        );
        w.openings[HIDX_I][INPUT_TAKE_ID_OFF] = 7;
        assert_eq!(
            check_insert_keys(&w.openings),
            Err(ApplyWitnessError::InsertKey)
        );
    }

    #[test]
    fn wrong_insert_sell_id_rejected() {
        let engine = btree_engine_v1();
        let mut w = build_apply_witness(
            &engine,
            ConsensusValue::GENESIS_PARENT,
            Height(1),
            &crossing_i(),
            crossing_match(),
        );
        w.openings[HIDX_I][INPUT_SELL_ID_OFF] = 7;
        assert_eq!(
            check_insert_keys(&w.openings),
            Err(ApplyWitnessError::InsertKey)
        );
    }
}
