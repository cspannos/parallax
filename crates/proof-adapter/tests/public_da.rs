//! Q-DA-6: public-tier replication of [`HeightStatement`]. Not DAS. Not `π`.

use clob::testutil::{btree_engine_v1, limit_v1, owner};
use commitments::{public_statement_id, value_id};
use consensus_adapter::{height_statement, propose};
use evm_adapter::{AtomicApply, Ledger};
use proof_adapter::{
    InertReason, NoHeightStark, OnDecided, PublicStatementStore, SettlementGate, Unlock,
};
use protocol_types::{AssetId, CanonicalEncode, ConsensusValue, Height, Input, Side};

fn crossing_height() -> (
    ConsensusValue,
    protocol_types::HeightStatement,
    Vec<protocol_types::SettlementDelta>,
    Ledger,
) {
    let engine = btree_engine_v1();
    let inputs = vec![
        Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
        Input::Place(limit_v1(5, 2, Side::Buy, 10, 100, 1)),
    ];
    let stmt = height_statement(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
    let value = propose(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
    let mut scratch = engine.clone();
    let receipts = scratch.apply_all(inputs);
    let deltas: Vec<_> = receipts.into_iter().flat_map(|r| r.settlement).collect();
    let mut ledger = Ledger::new();
    for a in [AssetId(1), AssetId(2)] {
        ledger.genesis_fund(owner(1), a, 1_000_000);
        ledger.genesis_fund(owner(2), a, 1_000_000);
    }
    (value, stmt, deltas, ledger)
}

#[test]
fn consensus_value_is_not_the_public_blob() {
    let (value, stmt, _, _) = crossing_height();
    assert!(stmt.binds_value(&value));
    assert_ne!(stmt.pre_root, value.state_root);
    assert_eq!(stmt.encode_vec().len(), 178);
    assert_ne!(public_statement_id(&stmt), value_id(&value));
}

#[test]
fn withheld_blob_is_unavailable() {
    let (value, stmt, _, _) = crossing_height();
    let store = PublicStatementStore::new();
    assert!(!store.available_for(&value));
    assert!(store.get(stmt.height).is_none());
}

#[test]
fn publish_makes_statement_available() {
    let (value, stmt, _, _) = crossing_height();
    let mut store = PublicStatementStore::new();
    store.publish(stmt);
    assert!(store.available_for(&value));
    assert_eq!(store.get(stmt.height), Some(&stmt));
}

#[test]
fn four_replicas_share_the_same_digest() {
    let (_, stmt, _, _) = crossing_height();
    let want = public_statement_id(&stmt);
    let mut replicas = [
        PublicStatementStore::new(),
        PublicStatementStore::new(),
        PublicStatementStore::new(),
        PublicStatementStore::new(),
    ];
    for r in &mut replicas {
        r.publish(stmt);
        assert_eq!(r.digest(stmt.height), Some(want));
    }
}

#[test]
fn no_height_stark_does_not_unlock() {
    let (value, stmt, deltas, ledger) = crossing_height();
    let dir = tempfile::tempdir().unwrap();
    let apply = AtomicApply::open(dir.path().join("set.log"), ledger).unwrap();
    let mut g = SettlementGate::new(apply, NoHeightStark);
    let out = g
        .on_decided(
            &value,
            &deltas,
            &stmt,
            Some(&Unlock::Proof(b"not-pi".to_vec())),
        )
        .unwrap();
    assert_eq!(
        out,
        OnDecided::Inert {
            reason: InertReason::ProofInvalid
        }
    );
    assert_eq!(g.payload_count(), 0);
}
