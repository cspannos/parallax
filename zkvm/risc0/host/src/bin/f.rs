//! Prove `F` (the matcher) on RISC Zero (ADR 0025).
//!
//!   RISC0_DEV_MODE=0 PLX_F_REST=8000 PLX_F_EVENTS=8 cargo run --release -p host --bin f
//!
//! `PLX_F_REST` resting orders (`load_places`), then `PLX_F_EVENTS` mixed
//! events (`churn_tape`). `PLX_EXECUTE_ONLY=1` for cycles only;
//! `PLX_RECEIPT=succinct` for a recursive receipt. The journal must equal the
//! natively computed `HeightStatement` fields (`pre_root`, `post_root`,
//! `input_commitment`, `settlement_commitment`).
//!
//! `PLX_F_SCENARIO=crossing` proves the M6b two-Place crossing height on an
//! empty genesis book (rest 10@90 sell, take 10@100 buy). With
//! `PLX_F_FIXTURE=<dir>` the receipt (`f_crossing.receipt`, bincode) and the
//! image ID (`f_guest.id`, 8 LE u32) are written there for the
//! `proof-adapter` gate test.

use std::time::Instant;

use clob::testutil::{btree_engine, churn_tape, load_places};
use commitments::{commit_list_payload, Digest, INPUT_DOMAIN, RECEIPT_DOMAIN};
use methods::{F_GUEST_ELF, F_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().map_or(default, |v| v.parse().expect(name))
}

fn main() {
    if std::env::var("RISC0_DEV_MODE").ok().as_deref() == Some("1") {
        panic!("RISC0_DEV_MODE=1 is not π; refuse to run");
    }
    let rest = env_usize("PLX_F_REST", 8_000);
    let events = env_usize("PLX_F_EVENTS", 8);
    let crossing = std::env::var("PLX_F_SCENARIO").ok().as_deref() == Some("crossing");
    let mut e = btree_engine();
    let inputs = if crossing {
        use clob::testutil::limit;
        use protocol_types::{Input, Side};
        vec![
            Input::Place(limit(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit(5, 2, Side::Buy, 10, 100, 1)),
        ]
    } else {
        e.apply_all(load_places(rest));
        churn_tape(rest.max(1), events)
    };

    // Native statement fields, computed independently of `run_f`.
    let pre_root = e.state_root();
    let mut scratch = e.clone();
    let settlement: Vec<_> = scratch
        .apply_all(inputs.clone())
        .into_iter()
        .flat_map(|r| r.settlement)
        .collect();
    let want = clob::FClaim {
        hash: e.treap_hash(),
        id_rule: e.order_id_rule(),
        pre_root,
        post_root: scratch.state_root(),
        input_commitment: Digest::from_bytes(&commit_list_payload(&inputs), INPUT_DOMAIN),
        settlement_commitment: Digest::from_bytes(&commit_list_payload(&settlement), RECEIPT_DOMAIN),
    };

    let snapshot = e.snapshot().encode();
    let payload = commit_list_payload(&inputs);
    let mut bytes = (snapshot.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&snapshot);
    bytes.extend_from_slice(&payload);
    assert_eq!(clob::run_f(&snapshot, &payload).expect("native F"), want);

    let env = ExecutorEnv::builder().write_slice(&bytes).build().unwrap();
    let label = format!(
        "risc0 F {} ({:?}, snapshot {} B, settlement deltas {})",
        if crossing { "crossing".to_string() } else { format!("rest {rest} events {events}") },
        e.treap_hash(),
        snapshot.len(),
        settlement.len()
    );
    if std::env::var("PLX_EXECUTE_ONLY").ok().as_deref() == Some("1") {
        let t0 = Instant::now();
        let s = default_executor().execute(env, F_GUEST_ELF).expect("execute");
        assert_eq!(s.journal.bytes, want.to_bytes(), "journal = native statement");
        println!(
            "{label}: execute {} ms, cycles {}, segments {}",
            t0.elapsed().as_millis(),
            s.cycles(),
            s.segments.len()
        );
        return;
    }
    let opts = match std::env::var("PLX_RECEIPT").ok().as_deref() {
        None | Some("composite") => ProverOpts::default(),
        Some("succinct") => ProverOpts::succinct(),
        Some(other) => panic!("PLX_RECEIPT={other} (composite|succinct)"),
    };
    let t0 = Instant::now();
    let info = default_prover().prove_with_opts(env, F_GUEST_ELF, &opts).expect("prove");
    let prove_ms = t0.elapsed().as_millis();
    let receipt = info.receipt;
    assert_eq!(receipt.journal.bytes, want.to_bytes(), "journal = native statement");
    let t1 = Instant::now();
    receipt.verify(F_GUEST_ID).expect("verify");
    let verify_ms = t1.elapsed().as_millis();
    let bytes = bincode::serialize(&receipt).expect("serialize");
    let size = bytes.len();
    if let Ok(dir) = std::env::var("PLX_F_FIXTURE") {
        assert!(crossing, "fixtures are the crossing scenario");
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("f_crossing.receipt"), &bytes).unwrap();
        let id: Vec<u8> = F_GUEST_ID.iter().flat_map(|w| w.to_le_bytes()).collect();
        std::fs::write(dir.join("f_guest.id"), id).unwrap();
        println!("wrote fixture to {}", dir.display());
    }
    println!(
        "{label}: prove {prove_ms} ms, verify {verify_ms} ms, {size} B, cycles {}, segments {}",
        info.stats.total_cycles, info.stats.segments
    );
}
