//! Prove `book_step` on SP1 CPU. Default is **core** (grows with cycles).
//!
//!   SP1_PROVER=cpu cargo run --release -p tiny-f-script
//!   SP1_PROVER=cpu PLX_RECEIPT=compressed cargo run --release -p tiny-f-script
//!
//! Compressed is recursive STARK aggregation (constant size in cycles).
//! Not Groth16/PLONK. Not height π. Not an 8k book.

use std::time::Instant;

use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::{include_elf, Elf, ProvingKey, SP1Stdin};
use tiny_f_guest_logic::{
    bench_book, BENCH_R0P, BENCH_R0Q, BENCH_R1P, BENCH_R1Q, BENCH_TP, BENCH_TQ,
};

const ELF: Elf = include_elf!("tiny-f-program");

fn main() {
    sp1_sdk::utils::setup_logger();

    let expected = bench_book();
    let mut stdin = SP1Stdin::new();
    stdin.write(&BENCH_R0Q);
    stdin.write(&BENCH_R0P);
    stdin.write(&BENCH_R1Q);
    stdin.write(&BENCH_R1P);
    stdin.write(&BENCH_TQ);
    stdin.write(&BENCH_TP);

    let client = ProverClient::from_env();
    let pk = client.setup(ELF).expect("setup");
    let mode = std::env::var("PLX_RECEIPT").ok();
    let kind = match mode.as_deref() {
        None | Some("core") => "core",
        Some("compressed") => "compressed",
        Some("groth16" | "plonk") => panic!("pairing wrap is not this cell (Q-PRF-4)"),
        Some(other) => panic!("unknown PLX_RECEIPT={other} (core|compressed)"),
    };

    let t0 = Instant::now();
    let mut proof = {
        let req = client.prove(&pk, stdin);
        match kind {
            "compressed" => req.compressed().run().expect("prove compressed"),
            _ => req.core().run().expect("prove core"),
        }
    };
    let prove_ms = t0.elapsed().as_millis();

    let fill0 = proof.public_values.read::<u64>();
    let fill1 = proof.public_values.read::<u64>();
    let take_left = proof.public_values.read::<u64>();
    let n0 = proof.public_values.read::<u128>();
    let n1 = proof.public_values.read::<u128>();
    assert_eq!(fill0, expected.fill0);
    assert_eq!(fill1, expected.fill1);
    assert_eq!(take_left, expected.take_left);
    assert_eq!(n0, expected.n0);
    assert_eq!(n1, expected.n1);

    let t1 = Instant::now();
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("verify");
    let verify_ms = t1.elapsed().as_millis();

    let bytes = bincode::serialize(&proof).expect("serialize");
    println!(
        "sp1 book-step: prove {} ms, verify {} ms, {} bytes ({}, not Groth16)",
        prove_ms, verify_ms, bytes.len(), kind
    );
}
