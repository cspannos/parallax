//! Prove `F` (the matcher) on SP1 — comparison with RISC Zero (ADR 0025).
//!
//!   SP1_PROVER=cpu PLX_F_REST=1000 PLX_F_EVENTS=8 cargo run --release -p tiny-f-script --bin f
//!
//! Same inputs as `zkvm/risc0/host/src/bin/f.rs`: `PLX_F_REST` resting orders,
//! `PLX_F_EVENTS` mixed events. `PLX_EXECUTE_ONLY=1` reports cycles only;
//! `PLX_RECEIPT=compressed` for the recursive proof (default core). Public
//! values must equal the natively computed `FClaim`.

use std::time::Instant;

use clob::testutil::{btree_engine, churn_tape, load_places};
use commitments::{commit_list_payload, Digest, INPUT_DOMAIN, RECEIPT_DOMAIN};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{include_elf, Elf, ProvingKey, SP1Stdin};

const ELF: Elf = include_elf!("f-program");

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().map_or(default, |v| v.parse().expect(name))
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let rest = env_usize("PLX_F_REST", 8_000);
    let events = env_usize("PLX_F_EVENTS", 8);
    let mut e = btree_engine();
    e.apply_all(load_places(rest));
    let inputs = churn_tape(rest.max(1), events);

    let mut scratch = e.clone();
    let settlement: Vec<_> = scratch
        .apply_all(inputs.clone())
        .into_iter()
        .flat_map(|r| r.settlement)
        .collect();
    let want = clob::FClaim {
        hash: e.treap_hash(),
        id_rule: e.order_id_rule(),
        pre_root: e.state_root(),
        post_root: scratch.state_root(),
        input_commitment: Digest::from_bytes(&commit_list_payload(&inputs), INPUT_DOMAIN),
        settlement_commitment: Digest::from_bytes(&commit_list_payload(&settlement), RECEIPT_DOMAIN),
    };
    let snapshot = e.snapshot().encode();
    let payload = commit_list_payload(&inputs);
    assert_eq!(clob::run_f(&snapshot, &payload).expect("native F"), want);
    let mut bytes = (snapshot.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&snapshot);
    bytes.extend_from_slice(&payload);
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);

    let client = ProverClient::from_env();
    let label = format!("sp1 F rest {rest} events {events} (snapshot {} B)", snapshot.len());
    if std::env::var("PLX_EXECUTE_ONLY").ok().as_deref() == Some("1") {
        let t0 = Instant::now();
        let (pv, report) = client.execute(ELF, stdin).run().expect("execute");
        assert_eq!(pv.as_slice(), &want.to_bytes()[..], "public values = native statement");
        println!(
            "{label}: execute {} ms, cycles {}",
            t0.elapsed().as_millis(),
            report.total_instruction_count()
        );
        return;
    }
    let pk = client.setup(ELF).expect("setup");
    let kind = match std::env::var("PLX_RECEIPT").ok().as_deref() {
        None | Some("core") => "core",
        Some("compressed") => "compressed",
        Some(other) => panic!("PLX_RECEIPT={other} (core|compressed)"),
    };
    let t0 = Instant::now();
    let proof = {
        let req = client.prove(&pk, stdin);
        match kind {
            "compressed" => req.compressed().run().expect("prove compressed"),
            _ => req.core().run().expect("prove core"),
        }
    };
    let prove_ms = t0.elapsed().as_millis();
    assert_eq!(proof.public_values.as_slice(), &want.to_bytes()[..], "public values = native statement");
    let t1 = Instant::now();
    client.verify(&proof, pk.verifying_key(), None).expect("verify");
    let verify_ms = t1.elapsed().as_millis();
    let size = bincode::serialize(&proof).expect("serialize").len();
    println!("{label}: prove {prove_ms} ms ({kind}), verify {verify_ms} ms, {size} B");
}
