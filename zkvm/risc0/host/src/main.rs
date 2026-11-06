//! Prove `book_step` on RISC Zero. Real receipt only (`disable-dev-mode`).
//!
//!   RISC0_DEV_MODE=0 cargo run --release -p host
//!   RISC0_DEV_MODE=0 PLX_RECEIPT=succinct cargo run --release -p host
//!
//! Composite is the default STARK receipt. Succinct is recursive STARK
//! compression (constant size in cycles). Not Groth16. Not height π. Not
//! an 8k book.

use std::time::Instant;

use methods::{TINY_F_GUEST_ELF, TINY_F_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, Prover, ProverOpts};
use tiny_f_guest_logic::{
    bench_book, BENCH_R0P, BENCH_R0Q, BENCH_R1P, BENCH_R1Q, BENCH_TP, BENCH_TQ,
};

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

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let expected = bench_book();
    let env = ExecutorEnv::builder()
        .write(&BENCH_R0Q)
        .unwrap()
        .write(&BENCH_R0P)
        .unwrap()
        .write(&BENCH_R1Q)
        .unwrap()
        .write(&BENCH_R1P)
        .unwrap()
        .write(&BENCH_TQ)
        .unwrap()
        .write(&BENCH_TP)
        .unwrap()
        .build()
        .unwrap();

    let opts = receipt_opts();
    let prover = default_prover();
    let t0 = Instant::now();
    let prove_info = prover
        .prove_with_opts(env, TINY_F_GUEST_ELF, &opts)
        .expect("prove");
    let prove_ms = t0.elapsed().as_millis();
    let receipt = prove_info.receipt;
    let kind = inner_kind(&receipt.inner);
    assert_ne!(kind, "groth16", "pairing wrap is not this cell");
    assert_ne!(kind, "fake", "dev-mode receipt is not π");

    let (fill0, fill1, take_left, n0, n1): (u64, u64, u64, u128, u128) =
        receipt.journal.decode().unwrap();
    assert_eq!(fill0, expected.fill0);
    assert_eq!(fill1, expected.fill1);
    assert_eq!(take_left, expected.take_left);
    assert_eq!(n0, expected.n0);
    assert_eq!(n1, expected.n1);

    let t1 = Instant::now();
    receipt.verify(TINY_F_GUEST_ID).expect("verify");
    let verify_ms = t1.elapsed().as_millis();

    let bytes = bincode::serialize(&receipt).expect("serialize receipt");
    println!(
        "risc0 book-step: prove {} ms, verify {} ms, {} bytes, kind {}, cycles {:?}",
        prove_ms,
        verify_ms,
        bytes.len(),
        kind,
        prove_info.stats,
    );
}
