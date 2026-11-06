//! 14 C' map hashes + `I` + genesis `C` + settlement + post `C'` stacked with this
//! height's match-step as [`VerifyPi`]. Last digest is `post_root`. Genesis INC
//! hashes to `pre_root`. Parent is `GENESIS_PARENT`. Settlement 277 B hashes to
//! `settlement_commitment`. Base amounts equal fill; quote amounts equal
//! notional. Maker account equals the rest leaf owner and the first Place
//! in `I`; taker equals the take Place. First Place qty/price equal match rest.
//! First Place id/instrument/side equal the rest leaf. Take Place
//! id/instrument are `from_u128(5)` / instrument 1. First Place expiry/nonce
//! equal the rest leaf. Take Place expiry/nonce equal the same constants.
//! Rest `TimeSeq` is `TimeSeq(0)`, not post `next_time`. Rest left/right
//! children are `treap_empty_digest()`. Domain / version / key_len /
//! OrderId key / value_len / `RESTING` tag are the 216 B header.
//! Seen/nonce share `TREAP_NODE_DOMAIN` / version / lens; prio share
//! `TREAP_PRIO_DOMAIN`. First key byte is 1 or 2 by `hidx`. `I` is
//! `INPUT_DOMAIN` / version / payload_len 206 / count 2 / two `INPLACE`+`ORDER`
//! tags. Tape is [`ApplyWitness`]. Not `F`. Settlement stays inert.

use clob::testutil::{btree_engine_v1, limit_v1, owner};
use commitments::public_statement_id;
use consensus_adapter::propose;
use evm_adapter::{AtomicApply, Ledger};
use proof_adapter::{
    build_apply_witness, check_apply_witness, height_match_pi_from_apply, ApplyWitness,
    HeightMatchVerifier, InertReason, OnDecided, SettlementGate, Unlock, VerifyPi,
};
use proof_plonky3::{
    encode_height_match_pi, prove_height_match_with, prove_tiny_with, FriClass,
    HEIGHT_MATCH_OPENINGS,
};
use protocol_types::{AssetId, ConsensusValue, Height, Input, Price, Qty, Side};
use tiny_f::{MatchStepInstance, MatchStepStatement, TinyInstance, TinyStatement};

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

fn apply_witness_fixture() -> (ApplyWitness, ConsensusValue, Vec<protocol_types::SettlementDelta>, Ledger)
{
    let engine = btree_engine_v1();
    let inputs = crossing_i();
    let w = build_apply_witness(
        &engine,
        ConsensusValue::GENESIS_PARENT,
        Height(1),
        &inputs,
        crossing_match(),
    );
    check_apply_witness(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &w).unwrap();
    assert_eq!(w.openings.len(), HEIGHT_MATCH_OPENINGS);
    let value = propose(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
    let mut scratch = engine.clone();
    let receipts = scratch.apply_all(inputs.iter().cloned());
    let deltas: Vec<_> = receipts
        .iter()
        .flat_map(|r| r.settlement.iter().cloned())
        .collect();
    let mut ledger = Ledger::new();
    for a in [AssetId(1), AssetId(2)] {
        ledger.genesis_fund(owner(1), a, 1_000_000);
        ledger.genesis_fund(owner(2), a, 1_000_000);
    }
    (w, value, deltas, ledger)
}

fn envelope_from_witness(w: &ApplyWitness, class: FriClass) -> Vec<u8> {
    height_match_pi_from_apply(w, class).unwrap()
}

#[test]
fn apply_witness_feeds_height_match() {
    let (w, _, _, _) = apply_witness_fixture();
    let bytes = envelope_from_witness(&w, FriClass::Test);
    HeightMatchVerifier::test()
        .verify(&w.statement, &bytes)
        .unwrap();
}

#[test]
fn matching_statement_verifies() {
    let (w, _, _, _) = apply_witness_fixture();
    let bytes = envelope_from_witness(&w, FriClass::Test);
    HeightMatchVerifier::test()
        .verify(&w.statement, &bytes)
        .unwrap();
}

#[test]
fn wrong_statement_rejected() {
    let (w, _, _, _) = apply_witness_fixture();
    let bytes = envelope_from_witness(&w, FriClass::Test);
    let mut other = w.statement;
    other.post_root = other.pre_root;
    assert!(HeightMatchVerifier::test().verify(&other, &bytes).is_err());
}

#[test]
fn wrong_height_rejected() {
    let (w, _, _, _) = apply_witness_fixture();
    let mut other = w.statement;
    other.height = Height(2);
    let proof = prove_height_match_with(w.openings.clone(), w.match_step, FriClass::Test).unwrap();
    let bytes = encode_height_match_pi(
        public_statement_id(&other).0,
        &w.openings,
        &w.match_step,
        &proof,
    );
    assert!(HeightMatchVerifier::test().verify(&other, &bytes).is_err());
}

#[test]
fn wrong_parent_rejected() {
    let (w, _, _, _) = apply_witness_fixture();
    let mut other = w.statement;
    other.parent = protocol_types::Bytes32([1; 32]);
    let proof = prove_height_match_with(w.openings.clone(), w.match_step, FriClass::Test).unwrap();
    let bytes = encode_height_match_pi(
        public_statement_id(&other).0,
        &w.openings,
        &w.match_step,
        &proof,
    );
    assert!(HeightMatchVerifier::test().verify(&other, &bytes).is_err());
}

#[test]
fn wrong_pre_root_rejected() {
    let (w, _, _, _) = apply_witness_fixture();
    let mut other = w.statement;
    other.pre_root = other.post_root;
    let proof = prove_height_match_with(w.openings.clone(), w.match_step, FriClass::Test).unwrap();
    let bytes = encode_height_match_pi(
        public_statement_id(&other).0,
        &w.openings,
        &w.match_step,
        &proof,
    );
    assert!(HeightMatchVerifier::test().verify(&other, &bytes).is_err());
}

#[test]
fn wrong_settlement_rejected() {
    let (w, _, _, _) = apply_witness_fixture();
    let mut other = w.statement;
    other.settlement_commitment = other.input_commitment;
    let proof = prove_height_match_with(w.openings.clone(), w.match_step, FriClass::Test).unwrap();
    let bytes = encode_height_match_pi(
        public_statement_id(&other).0,
        &w.openings,
        &w.match_step,
        &proof,
    );
    assert!(HeightMatchVerifier::test().verify(&other, &bytes).is_err());
}

#[test]
fn tiny_f_bytes_rejected() {
    let (w, _, _, _) = apply_witness_fixture();
    let fill = TinyStatement::prove_native(TinyInstance {
        maker_qty: Qty(10),
        taker_qty: Qty(7),
        price: Price(90),
    })
    .unwrap();
    let proof = prove_tiny_with(fill, FriClass::Test).unwrap();
    assert!(HeightMatchVerifier::test()
        .verify(&w.statement, &proof.bytes)
        .is_err());
}

#[test]
fn garbage_rejected() {
    let (w, _, _, _) = apply_witness_fixture();
    assert!(HeightMatchVerifier::test()
        .verify(&w.statement, b"not-a-stark")
        .is_err());
}

#[test]
fn valid_stack_does_not_unlock_settlement() {
    let (w, value, deltas, ledger) = apply_witness_fixture();
    let bytes = envelope_from_witness(&w, FriClass::Test);
    HeightMatchVerifier::test()
        .verify(&w.statement, &bytes)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let apply = AtomicApply::open(dir.path().join("set.log"), ledger).unwrap();
    let mut g = SettlementGate::new(apply, HeightMatchVerifier::test());
    let out = g
        .on_decided(&value, &deltas, &w.statement, Some(&Unlock::Proof(bytes)))
        .unwrap();
    assert_eq!(
        out,
        OnDecided::Inert {
            reason: InertReason::ProofInvalid
        }
    );
    assert_eq!(g.payload_count(), 0);
    assert_eq!(g.eth_get_balance(owner(2), AssetId(2)), 1_000_000);
}

#[test]
fn match_verifier_is_verify_pi() {
    fn assert_pi<V: VerifyPi>(_: &V) {}
    assert_pi(&HeightMatchVerifier::test());
    assert!(!<HeightMatchVerifier as VerifyPi>::UNLOCKS_SETTLEMENT);
}

#[cfg(not(debug_assertions))]
#[test]
fn height_match_prod_verify_through_object() {
    let (w, _, _, _) = apply_witness_fixture();
    let t0 = std::time::Instant::now();
    let bytes = envelope_from_witness(&w, FriClass::Prod);
    let prove_ms = t0.elapsed().as_millis();
    let v = HeightMatchVerifier::prod();
    let t1 = std::time::Instant::now();
    v.verify(&w.statement, &bytes).unwrap();
    let verify_ms = t1.elapsed().as_millis();
    assert!(bytes.len() > 10_000);
    eprintln!(
        "height-match HeightMatchVerifier prod: prove {} ms, verify {} ms, {} bytes (ApplyWitness tape → HeightMatch; 14 C' map hashes + I + genesis C + settlement + post C' + match-step, last digest = post_root, not F, UNLOCKS_SETTLEMENT=false)",
        prove_ms, verify_ms, bytes.len()
    );
}
