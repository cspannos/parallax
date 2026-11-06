//! Prove a general `C'` update ([`IncTape`], ADR 0022) on RISC Zero.
//!
//!   RISC0_DEV_MODE=0 PLX_TAPE=place cargo run --release -p host --bin tape
//!   RISC0_DEV_MODE=0 PLX_TAPE=churn:64 PLX_RECEIPT=succinct cargo run --release -p host --bin tape
//!
//! `PLX_TAPE`: `place` (one Place at 8k) or `churn:N` (`churn_tape(8000, N)`
//! at 8k). `PLX_EXECUTE_ONLY=1` runs the executor (cycles, no proof).
//! `PLX_HASH=blake3` uses `C'` v1 (BLAKE3); the default is SHA-256 (ADR 0024).
//! The receipt's journal must equal the engine's `C` / `C'`. Not `F`.

use std::time::Instant;

use clob::testutil::{btree_engine, churn_tape, limit, load_places};
use clob::{start_inc_step_trace, take_inc_step_trace};
use commitments::IncTape;
use methods::{INC_TAPE_GUEST_ELF, INC_TAPE_GUEST_ID};
use protocol_types::{Input, Side};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, InnerReceipt, ProverOpts};

fn receipt_opts() -> ProverOpts {
    match std::env::var("PLX_RECEIPT").ok().as_deref() {
        None | Some("composite") => ProverOpts::default(),
        Some("succinct") => ProverOpts::succinct(),
        Some("groth16") => panic!("Groth16 wrap is not this cell (Q-PRF-4)"),
        Some(other) => panic!("unknown PLX_RECEIPT={other} (composite|succinct)"),
    }
}

fn inner_kind(inner: &InnerReceipt) -> &'static str {
    match inner {
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Succinct(_) => "succinct",
        InnerReceipt::Groth16(_) => "groth16",
        InnerReceipt::Fake(_) => "fake",
        _ => "other",
    }
}

fn main() {
    if std::env::var("RISC0_DEV_MODE").ok().as_deref() == Some("1") {
        panic!("RISC0_DEV_MODE=1 is not π; refuse to run");
    }
    let which = std::env::var("PLX_TAPE").unwrap_or_else(|_| "place".into());
    let inputs = match which.as_str() {
        "place" => vec![Input::Place(limit(8_001, 2, Side::Buy, 1, 50, 1))],
        s if s.starts_with("churn:") => churn_tape(8_000, s[6..].parse().expect("churn:N")),
        other => panic!("unknown PLX_TAPE={other} (place|churn:N)"),
    };
    let n_inputs = inputs.len();

    let mut e = btree_engine();
    match std::env::var("PLX_HASH").ok().as_deref() {
        None | Some("sha256") => {}
        Some("blake3") => e.set_treap_hash(clob::TreapHash::Blake3),
        Some(other) => panic!("unknown PLX_HASH={other} (blake3|sha256)"),
    }
    e.apply_all(load_places(8_000));
    let pre_root = e.state_root();
    let pre = e.incremental_inc_header();
    let (n, s, r) = e.incremental_map_roots();
    start_inc_step_trace();
    e.apply_all(inputs);
    let steps = take_inc_step_trace();
    let post_root = e.state_root();
    let tape = IncTape { hash: e.treap_hash(), pre, pre_maps: [n, s, r], steps, post: e.incremental_inc_header() };
    let claim = tape.verify().expect("native tape");
    assert_eq!((claim.pre_root, claim.post_root), (pre_root, post_root));
    let bytes = tape.encode();

    let env = ExecutorEnv::builder().write_slice(&bytes).build().unwrap();
    if std::env::var("PLX_EXECUTE_ONLY").ok().as_deref() == Some("1") {
        let t0 = Instant::now();
        let session = default_executor().execute(env, INC_TAPE_GUEST_ELF).expect("execute");
        println!(
            "risc0 inc-tape {which} {:?}: inputs {n_inputs}, steps {}, node {}, prio {}, witness {} B, \
             execute {} ms, cycles {}, segments {}",
            e.treap_hash(),
            claim.steps,
            claim.node_hashes,
            claim.prio_hashes,
            bytes.len(),
            t0.elapsed().as_millis(),
            session.cycles(),
            session.segments.len(),
        );
        return;
    }

    let opts = receipt_opts();
    let t0 = Instant::now();
    let info = default_prover()
        .prove_with_opts(env, INC_TAPE_GUEST_ELF, &opts)
        .expect("prove");
    let prove_ms = t0.elapsed().as_millis();
    let receipt = info.receipt;
    let kind = inner_kind(&receipt.inner);
    assert!(kind != "groth16" && kind != "fake", "{kind} is not this cell");

    let j = &receipt.journal.bytes;
    assert_eq!(j.len(), 100);
    assert_eq!(&j[..32], &pre_root.0, "journal pre_root = engine C");
    assert_eq!(&j[32..64], &post_root.0, "journal post_root = engine C'");
    assert_eq!(&j[64..96], &claim.ops.0, "journal ops");

    let t1 = Instant::now();
    receipt.verify(INC_TAPE_GUEST_ID).expect("verify");
    let verify_ms = t1.elapsed().as_millis();
    let size = bincode::serialize(&receipt).expect("serialize").len();
    println!(
        "risc0 inc-tape {which} {:?}: inputs {n_inputs}, steps {}, node {}, prio {}, witness {} B, \
         prove {prove_ms} ms, verify {verify_ms} ms, {size} B, kind {kind}, cycles {}, segments {}",
        e.treap_hash(),
        claim.steps,
        claim.node_hashes,
        claim.prio_hashes,
        bytes.len(),
        info.stats.total_cycles,
        info.stats.segments,
    );
}
