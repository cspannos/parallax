//! ADR 0025: a RISC Zero `π` of `F` unlocks settlement through
//! [`SettlementGate`]; anything else stays inert.
//!
//! Fixture (real succinct receipt of the M6b crossing height, production
//! SHA-256 `C'`), regenerated with:
//!
//!   RISC0_DEV_MODE=0 PLX_RECEIPT=succinct PLX_F_SCENARIO=crossing \
//!     PLX_F_FIXTURE=crates/proof-adapter/tests/fixtures \
//!     cargo run --release -p host --bin f --manifest-path zkvm/risc0/Cargo.toml
//!
//!   cargo test -p proof-adapter --features risc0 --test risc0_gate
#![cfg(feature = "risc0")]

use clob::testutil::{btree_engine, limit, owner};
use consensus_adapter::{height_statement, propose};
use evm_adapter::{AtomicApply, Ledger};
use proof_adapter::{InertReason, OnDecided, Risc0FVerifier, SettlementGate, Unlock};
use protocol_types::{AssetId, ConsensusValue, Height, HeightStatement, Input, Side};

const RECEIPT: &[u8] = include_bytes!("fixtures/f_crossing.receipt");
const IMAGE_ID: &[u8] = include_bytes!("fixtures/f_guest.id");

fn image_id() -> [u32; 8] {
    std::array::from_fn(|i| u32::from_le_bytes(IMAGE_ID[4 * i..4 * i + 4].try_into().unwrap()))
}

fn crossing(inputs: Vec<Input>) -> (ConsensusValue, Vec<protocol_types::SettlementDelta>, HeightStatement) {
    let engine = btree_engine();
    let stmt = height_statement(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
    let value = propose(&engine, ConsensusValue::GENESIS_PARENT, Height(1), &inputs);
    let deltas = engine
        .clone()
        .apply_all(inputs)
        .into_iter()
        .flat_map(|r| r.settlement)
        .collect();
    (value, deltas, stmt)
}

fn inputs() -> Vec<Input> {
    vec![
        Input::Place(limit(1, 1, Side::Sell, 10, 90, 1)),
        Input::Place(limit(5, 2, Side::Buy, 10, 100, 1)),
    ]
}

fn gate(id: [u32; 8]) -> (tempfile::TempDir, SettlementGate<Risc0FVerifier>) {
    let mut ledger = Ledger::new();
    for a in [AssetId(1), AssetId(2)] {
        ledger.genesis_fund(owner(1), a, 1_000_000);
        ledger.genesis_fund(owner(2), a, 1_000_000);
    }
    let dir = tempfile::tempdir().unwrap();
    let apply = AtomicApply::open(dir.path().join("set.log"), ledger).unwrap();
    (dir, SettlementGate::new(apply, Risc0FVerifier { image_id: id }))
}

#[test]
fn risc0_f_receipt_unlocks_settlement() {
    let (value, deltas, stmt) = crossing(inputs());
    let (_d, mut g) = gate(image_id());
    let before = g.eth_get_balance(owner(1), AssetId(2));
    let out = g
        .on_decided(&value, &deltas, &stmt, Some(&Unlock::Proof(RECEIPT.to_vec())))
        .unwrap();
    assert!(matches!(out, OnDecided::Settled(_)), "{out:?}");
    assert_ne!(g.eth_get_balance(owner(1), AssetId(2)), before, "money moved");
}

#[test]
fn receipt_for_another_height_stays_inert() {
    // Same proof, different `I` (take 5 instead of 10): statement fields differ.
    let mut other = inputs();
    other[1] = Input::Place(limit(5, 2, Side::Buy, 5, 100, 1));
    let (value, deltas, stmt) = crossing(other);
    let (_d, mut g) = gate(image_id());
    let out = g
        .on_decided(&value, &deltas, &stmt, Some(&Unlock::Proof(RECEIPT.to_vec())))
        .unwrap();
    assert_eq!(out, OnDecided::Inert { reason: InertReason::ProofInvalid });
}

#[test]
fn wrong_image_or_tampered_receipt_stays_inert() {
    let (value, deltas, stmt) = crossing(inputs());
    let mut wrong = image_id();
    wrong[0] ^= 1;
    let (_d, mut g) = gate(wrong);
    let out = g
        .on_decided(&value, &deltas, &stmt, Some(&Unlock::Proof(RECEIPT.to_vec())))
        .unwrap();
    assert_eq!(out, OnDecided::Inert { reason: InertReason::ProofInvalid });

    let (_d, mut g) = gate(image_id());
    for at in [RECEIPT.len() / 3, RECEIPT.len() / 2, RECEIPT.len() - 40] {
        let mut bad = RECEIPT.to_vec();
        bad[at] ^= 1;
        let out = g.on_decided(&value, &deltas, &stmt, Some(&Unlock::Proof(bad))).unwrap();
        assert_eq!(out, OnDecided::Inert { reason: InertReason::ProofInvalid }, "flip at {at}");
    }
}
