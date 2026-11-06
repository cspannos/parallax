//! M6b: decide without unlock does not move money.

use clob::testutil::{btree_engine_v1, limit_v1, owner};
use consensus_adapter::{height_statement, propose};
use evm_adapter::{AtomicApply, Ledger};
use proof_adapter::{InertReason, OnDecided, SettlementGate, Unlock, VerifyError, VerifyPi};
use protocol_types::{AssetId, ConsensusValue, Height, HeightStatement, Input, Side};

struct TestVerifier {
    accept: bool,
}

impl VerifyPi for TestVerifier {
    /// Abstract stand-in for height `π`. Not a STARK of `C'`.
    const UNLOCKS_SETTLEMENT: bool = true;

    fn verify(&self, _statement: &HeightStatement, _proof: &[u8]) -> Result<(), VerifyError> {
        if self.accept {
            Ok(())
        } else {
            Err(VerifyError)
        }
    }
}

fn matched_height() -> (
    ConsensusValue,
    Vec<protocol_types::SettlementDelta>,
    Ledger,
    HeightStatement,
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
    (value, deltas, ledger, stmt)
}

fn gate_keep_dir(
    ledger: Ledger,
    accept: bool,
) -> (tempfile::TempDir, SettlementGate<TestVerifier>) {
    let dir = tempfile::tempdir().unwrap();
    let apply = AtomicApply::open(dir.path().join("set.log"), ledger).unwrap();
    (dir, SettlementGate::new(apply, TestVerifier { accept }))
}

#[test]
fn missing_unlock_does_not_apply() {
    let (value, deltas, ledger, stmt) = matched_height();
    let (_dir, mut g) = gate_keep_dir(ledger, true);
    let out = g.on_decided(&value, &deltas, &stmt, None).unwrap();
    assert_eq!(
        out,
        OnDecided::Inert {
            reason: InertReason::MissingWitness
        }
    );
    assert_eq!(g.payload_count(), 0);
    assert!(g.settled().is_none());
    assert_eq!(g.eth_get_balance(owner(2), AssetId(2)), 1_000_000);
}

#[test]
fn invalid_proof_does_not_apply() {
    let (value, deltas, ledger, stmt) = matched_height();
    let (_dir, mut g) = gate_keep_dir(ledger, false);
    let out = g
        .on_decided(
            &value,
            &deltas,
            &stmt,
            Some(&Unlock::Proof(b"not-a-stark".to_vec())),
        )
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
fn statement_mismatch_does_not_apply() {
    let (value, deltas, ledger, mut stmt) = matched_height();
    stmt.post_root = stmt.pre_root;
    let (_dir, mut g) = gate_keep_dir(ledger, true);
    let out = g
        .on_decided(&value, &deltas, &stmt, Some(&Unlock::FullViewCertificate))
        .unwrap();
    assert_eq!(
        out,
        OnDecided::Inert {
            reason: InertReason::StatementMismatch
        }
    );
    assert_eq!(g.payload_count(), 0);
    assert_eq!(g.eth_get_balance(owner(2), AssetId(2)), 1_000_000);
}

#[test]
fn full_view_certificate_applies_without_pi() {
    let (value, deltas, ledger, stmt) = matched_height();
    let (_dir, mut g) = gate_keep_dir(ledger, false);
    let out = g
        .on_decided(&value, &deltas, &stmt, Some(&Unlock::FullViewCertificate))
        .unwrap();
    assert!(matches!(out, OnDecided::Settled(_)));
    assert_eq!(g.payload_count(), 1);
    assert!(g.eth_get_balance(owner(2), AssetId(2)) < 1_000_000);
}

#[test]
fn test_verifier_accept_is_not_labeled_as_snark() {
    let (value, deltas, ledger, stmt) = matched_height();
    let (_dir, mut g) = gate_keep_dir(ledger, true);
    let out = g
        .on_decided(
            &value,
            &deltas,
            &stmt,
            Some(&Unlock::Proof(b"test-verifier".to_vec())),
        )
        .unwrap();
    assert!(matches!(out, OnDecided::Settled(_)));
}

#[test]
fn later_valid_unlock_can_settle_inert_height() {
    let (value, deltas, ledger, stmt) = matched_height();
    let (_dir, mut g) = gate_keep_dir(ledger, true);
    let _ = g.on_decided(&value, &deltas, &stmt, None).unwrap();
    assert!(g.settled().is_none());
    let out = g
        .on_decided(&value, &deltas, &stmt, Some(&Unlock::FullViewCertificate))
        .unwrap();
    assert!(matches!(out, OnDecided::Settled(_)));
}

/// Tiered finality (ADR 0031): with a finality requirement, a valid `π` is not
/// enough. Settlement needs 2f+1 hybrid finality signatures on this value.
#[test]
fn tiered_finality_gates_settlement() {
    use std::sync::Arc;

    use consensus_adapter::finality::{Collector, FinalityCertificate, FinalitySig};
    use crypto_suite::{SuitePolicy, SuiteSigningKey};
    use protocol_types::CryptoSuiteId;

    let (value, deltas, ledger, stmt) = matched_height();
    let keys: Vec<_> = (0..4u8)
        .map(|i| SuiteSigningKey::from_seed(CryptoSuiteId::HybridV1, [i + 1; 32]))
        .collect();
    let roster = Arc::new(keys.iter().map(|k| k.public()).collect::<Vec<_>>());
    let id = commitments::value_id(&value);
    let cert_for = |id| -> FinalityCertificate {
        let mut c = Collector::new(SuitePolicy::HYBRID, roster.clone());
        let mut out = None;
        for (i, k) in keys.iter().enumerate().take(3) {
            out = c.add(FinalitySig::sign(k, i as u16, 1, id)).unwrap();
        }
        out.unwrap()
    };
    let proof = Unlock::Proof(vec![1]);
    let (_dir, g) = gate_keep_dir(ledger, true);
    let mut g = g.require_finality(SuitePolicy::HYBRID, roster.clone());

    // Proof alone: inert.
    let out = g.on_decided(&value, &deltas, &stmt, Some(&proof)).unwrap();
    assert_eq!(out, OnDecided::Inert { reason: InertReason::MissingFinality });
    // Certificate on another value: inert.
    let wrong = cert_for(commitments::Digest([9; 32]));
    let out = g.on_decided_final(&value, &deltas, &stmt, Some(&proof), Some(&wrong)).unwrap();
    assert_eq!(out, OnDecided::Inert { reason: InertReason::FinalityInvalid });
    // Below quorum: inert.
    let mut short = cert_for(id);
    short.sigs.pop();
    let out = g.on_decided_final(&value, &deltas, &stmt, Some(&proof), Some(&short)).unwrap();
    assert_eq!(out, OnDecided::Inert { reason: InertReason::FinalityInvalid });
    assert_eq!(g.payload_count(), 0);
    // Certificate + proof: settles.
    let out = g.on_decided_final(&value, &deltas, &stmt, Some(&proof), Some(&cert_for(id))).unwrap();
    assert!(matches!(out, OnDecided::Settled(_)));
}
