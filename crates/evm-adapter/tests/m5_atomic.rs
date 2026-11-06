//! M5: privileged batch apply, both roots, crash without split-brain.

use clob::testutil::{btree_engine, limit, owner};
use consensus_adapter::{commit_list, propose};
use evm_adapter::{settlement_commitment, ApplyError, AtomicApply, Ledger, PayloadStatus};
use protocol_types::{AssetId, ConsensusValue, Height, Input, Side};

fn matched_height() -> (ConsensusValue, Vec<protocol_types::SettlementDelta>, Ledger) {
    let engine = btree_engine();
    let inputs = vec![
        Input::Place(limit(1, 1, Side::Sell, 10, 90, 1)),
        Input::Place(limit(2, 2, Side::Buy, 10, 100, 1)),
    ];
    let value = propose(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
    let mut scratch = engine.clone();
    let receipts = scratch.apply_all(inputs);
    let deltas: Vec<_> = receipts.into_iter().flat_map(|r| r.settlement).collect();
    assert_eq!(settlement_commitment(&deltas), value.settlement_commitment);
    assert_eq!(
        commit_list(&deltas, commitments::RECEIPT_DOMAIN).to_bytes32(),
        value.settlement_commitment
    );

    let mut ledger = Ledger::new();
    for a in [AssetId(1), AssetId(2)] {
        ledger.genesis_fund(owner(1), a, 1_000_000);
        ledger.genesis_fund(owner(2), a, 1_000_000);
    }
    (value, deltas, ledger)
}

#[test]
fn both_roots_match_one_payload_not_per_delta() {
    let dir = tempfile::tempdir().unwrap();
    let (value, deltas, ledger) = matched_height();
    assert!(deltas.len() > 1);
    let mut apply = AtomicApply::open(dir.path().join("set.log"), ledger).unwrap();
    let settled = apply.apply_decided(&value, &deltas).unwrap();
    assert_eq!(settled.height, 1);
    assert_eq!(settled.pse_root, value.state_root);
    assert_eq!(settled.evm_root, apply.settled().unwrap().evm_root);
    assert_eq!(apply.payload_count(), 1);
    assert_ne!(settled.evm_root, protocol_types::Bytes32::ZERO);
    let quote_taker = apply.eth_get_balance(owner(2), AssetId(2));
    assert!(quote_taker < 1_000_000, "taker spent quote");
}

#[test]
fn mismatch_commitment_does_not_touch_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let (mut value, deltas, ledger) = matched_height();
    value.settlement_commitment = protocol_types::Bytes32([0xab; 32]);
    let mut apply = AtomicApply::open(dir.path().join("set.log"), ledger).unwrap();
    let err = apply.apply_decided(&value, &deltas).unwrap_err();
    assert!(matches!(err, ApplyError::CommitmentMismatch));
    assert_eq!(apply.payload_count(), 0);
    assert!(apply.settled().is_none());
}

#[test]
fn crash_after_intent_is_not_settled_until_retry() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("set.log");
    let (value, deltas, ledger) = matched_height();
    let funded = ledger.clone();
    {
        let mut apply = AtomicApply::open(&log, ledger).unwrap();
        apply.crash_after_intent = true;
        let err = apply.apply_decided(&value, &deltas).unwrap_err();
        assert!(matches!(err, ApplyError::SimulatedCrash));
        assert!(apply.settled().is_none());
        assert_eq!(apply.eth_get_balance(owner(2), AssetId(2)), 1_000_000);
    }
    let apply = AtomicApply::open(&log, funded.clone()).unwrap();
    assert!(apply.settled().is_none());
    assert_eq!(apply.eth_get_balance(owner(2), AssetId(2)), 1_000_000);

    let mut apply = AtomicApply::open(&log, funded).unwrap();
    let settled = apply.retry_pending().unwrap().expect("pending intent");
    assert_eq!(settled.pse_root, value.state_root);
    assert_eq!(apply.payload_count(), 1);
    assert!(apply.eth_get_balance(owner(2), AssetId(2)) < 1_000_000);
}

#[test]
fn debit_without_funds_invalidates_height() {
    let dir = tempfile::tempdir().unwrap();
    let (value, deltas, _funded) = matched_height();
    let mut apply = AtomicApply::open(dir.path().join("b.log"), Ledger::new()).unwrap();
    let err = apply.apply_decided(&value, &deltas).unwrap_err();
    assert!(matches!(err, ApplyError::InvalidPayload(_)));
    assert!(apply.settled().is_none());
}

#[test]
fn unexpected_syncing_after_decide_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let (value, deltas, ledger) = matched_height();
    let mut apply = AtomicApply::open(dir.path().join("set.log"), ledger).unwrap();
    apply.sidecar_mut().set_syncing(true);
    let err = apply.apply_decided(&value, &deltas).unwrap_err();
    assert!(matches!(err, ApplyError::Sidecar(_)));
    assert!(apply.settled().is_none());
}

#[test]
fn new_payload_syncing_status() {
    let mut s = evm_adapter::InProcessSidecar::new(Ledger::new());
    s.set_syncing(true);
    let st = s
        .new_payload(evm_adapter::SettlementPayload {
            parent_evm_root: s.head(),
            deltas: vec![],
        })
        .unwrap();
    assert_eq!(st, PayloadStatus::Syncing);
}
