//! Fourteen chrono C' map hashes (9 node + 5 prio) of the 2-place
//! `HeightStatement` height as [`VerifyPi`]. Not `F`. Not matching.
//! Settlement stays inert.

use clob::testutil::{btree_engine_v1, limit_v1, owner};
use commitments::{
    public_statement_id, start_c_prime_trace, take_c_prime_trace,
};
use consensus_adapter::{height_statement, propose};
use evm_adapter::{AtomicApply, Ledger};
use proof_adapter::{
    HeightOpeningsVerifier, InertReason, OnDecided, SettlementGate, Unlock, VerifyPi,
};
use proof_plonky3::{
    encode_height_pi, prove_height_openings_with, prove_tiny_with, FriClass, HEIGHT_OPENINGS,
};
use protocol_types::{AssetId, ConsensusValue, Height, Input, Side};
use tiny_f::{TinyInstance, TinyStatement};

fn crossing_i() -> Vec<Input> {
    vec![
        Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
        Input::Place(limit_v1(5, 2, Side::Buy, 10, 100, 1)),
    ]
}

fn height_pi_fixture() -> (
    protocol_types::HeightStatement,
    Vec<Vec<u8>>,
    ConsensusValue,
    Vec<protocol_types::SettlementDelta>,
    Ledger,
) {
    let mut engine = btree_engine_v1();
    engine.set_treap_hash(clob::TreapHash::Blake3Count);
    let inputs = crossing_i();
    let stmt = height_statement(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
    let value = propose(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
    start_c_prime_trace();
    let receipts = engine.apply_all(inputs);
    let openings = take_c_prime_trace();
    assert_eq!(openings.len(), HEIGHT_OPENINGS);
    let deltas: Vec<_> = receipts.into_iter().flat_map(|r| r.settlement).collect();
    let mut ledger = Ledger::new();
    for a in [AssetId(1), AssetId(2)] {
        ledger.genesis_fund(owner(1), a, 1_000_000);
        ledger.genesis_fund(owner(2), a, 1_000_000);
    }
    (stmt, openings, value, deltas, ledger)
}

fn envelope(
    stmt: &protocol_types::HeightStatement,
    openings: Vec<Vec<u8>>,
    class: FriClass,
) -> Vec<u8> {
    let proof = prove_height_openings_with(openings.clone(), class).unwrap();
    encode_height_pi(public_statement_id(stmt).0, &openings, &proof)
}

#[test]
fn matching_statement_verifies() {
    let (stmt, openings, _, _, _) = height_pi_fixture();
    let bytes = envelope(&stmt, openings, FriClass::Test);
    HeightOpeningsVerifier::test()
        .verify(&stmt, &bytes)
        .unwrap();
}

#[test]
fn wrong_statement_rejected() {
    let (stmt, openings, _, _, _) = height_pi_fixture();
    let bytes = envelope(&stmt, openings, FriClass::Test);
    let mut other = stmt;
    other.post_root = other.pre_root;
    assert!(HeightOpeningsVerifier::test()
        .verify(&other, &bytes)
        .is_err());
}

#[test]
fn tiny_f_bytes_rejected() {
    let (stmt, _, _, _, _) = height_pi_fixture();
    let fill = TinyStatement::prove_native(TinyInstance {
        maker_qty: protocol_types::Qty(10),
        taker_qty: protocol_types::Qty(7),
        price: protocol_types::Price(90),
    })
    .unwrap();
    let proof = prove_tiny_with(fill, FriClass::Test).unwrap();
    assert!(HeightOpeningsVerifier::test()
        .verify(&stmt, &proof.bytes)
        .is_err());
}

#[test]
fn garbage_rejected() {
    let (stmt, _, _, _, _) = height_pi_fixture();
    assert!(HeightOpeningsVerifier::test()
        .verify(&stmt, b"not-a-stark")
        .is_err());
}

#[test]
fn valid_openings_do_not_unlock_settlement() {
    let (stmt, openings, value, deltas, ledger) = height_pi_fixture();
    let bytes = envelope(&stmt, openings, FriClass::Test);
    HeightOpeningsVerifier::test()
        .verify(&stmt, &bytes)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let apply = AtomicApply::open(dir.path().join("set.log"), ledger).unwrap();
    let mut g = SettlementGate::new(apply, HeightOpeningsVerifier::test());
    let out = g
        .on_decided(&value, &deltas, &stmt, Some(&Unlock::Proof(bytes)))
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
fn openings_verifier_is_verify_pi() {
    fn assert_pi<V: VerifyPi>(_: &V) {}
    assert_pi(&HeightOpeningsVerifier::test());
    assert!(!<HeightOpeningsVerifier as VerifyPi>::UNLOCKS_SETTLEMENT);
}

#[cfg(not(debug_assertions))]
#[test]
fn height_openings_prod_verify_through_object() {
    let (stmt, openings, _, _, _) = height_pi_fixture();
    let t0 = std::time::Instant::now();
    let bytes = envelope(&stmt, openings, FriClass::Prod);
    let prove_ms = t0.elapsed().as_millis();
    let v = HeightOpeningsVerifier::prod();
    let t1 = std::time::Instant::now();
    v.verify(&stmt, &bytes).unwrap();
    let verify_ms = t1.elapsed().as_millis();
    assert!(bytes.len() > 10_000);
    eprintln!(
        "height-openings HeightOpeningsVerifier prod: prove {} ms, verify {} ms, {} bytes (14 C' map hashes, not F, not matching, UNLOCKS_SETTLEMENT=false)",
        prove_ms,
        verify_ms,
        bytes.len()
    );
}
