//! Chunked `C'` proof of one height (B4): prove `PLX_CHUNKS` tapes of
//! `PLX_CHUNK_EVENTS` mixed events each (succinct), then one `join` receipt
//! that verifies them recursively and chains their roots.
//!
//!   RISC0_DEV_MODE=0 PLX_CHUNKS=3 PLX_CHUNK_EVENTS=4 cargo run --release -p host --bin height
//!
//! `PLX_TAMPER=1` also re-executes the join on swapped / dropped / forged chunk
//! journals and requires each to fail.
//!
//! Chunks are independent and could prove on separate machines; this binary
//! proves them one after another. The final journal must equal the engine's
//! `C` before the first event and `C'` after the last. Not `F`.

use std::time::Instant;

use clob::testutil::{btree_engine, churn_tape, load_places};
use clob::{start_inc_step_trace, take_inc_step_trace};
use commitments::IncTape;
use methods::{INC_JOIN_GUEST_ELF, INC_JOIN_GUEST_ID, INC_TAPE_GUEST_ELF, INC_TAPE_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts, Receipt};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().map_or(default, |v| v.parse().expect(name))
}

fn main() {
    if std::env::var("RISC0_DEV_MODE").ok().as_deref() == Some("1") {
        panic!("RISC0_DEV_MODE=1 is not π; refuse to run");
    }
    let chunks = env_usize("PLX_CHUNKS", 3);
    let per = env_usize("PLX_CHUNK_EVENTS", 4);
    let inputs = churn_tape(8_000, chunks * per);

    let mut e = btree_engine();
    e.apply_all(load_places(8_000));
    let pre_root = e.state_root();

    let prover = default_prover();
    let opts = ProverOpts::succinct();
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut chunk_ms = Vec::new();
    let mut cycles = 0u64;
    let mut steps = 0usize;
    for chunk in inputs.chunks(per) {
        let pre = e.incremental_inc_header();
        let (n, s, r) = e.incremental_map_roots();
        start_inc_step_trace();
        e.apply_all(chunk.to_vec());
        let tape = IncTape {
            hash: e.treap_hash(),
            pre,
            pre_maps: [n, s, r],
            steps: take_inc_step_trace(),
            post: e.incremental_inc_header(),
        };
        steps += tape.steps.len();
        let env = ExecutorEnv::builder().write_slice(&tape.encode()).build().unwrap();
        let t0 = Instant::now();
        let info = prover.prove_with_opts(env, INC_TAPE_GUEST_ELF, &opts).expect("chunk");
        chunk_ms.push(t0.elapsed().as_millis());
        cycles += info.stats.total_cycles;
        eprintln!(
            "chunk {}: {} steps, {} cycles, {} ms",
            receipts.len(),
            tape.steps.len(),
            info.stats.total_cycles,
            chunk_ms.last().unwrap()
        );
        receipts.push(info.receipt);
    }
    let post_root = e.state_root();

    let journals: Vec<Vec<u8>> = receipts.iter().map(|r| r.journal.bytes.clone()).collect();
    if std::env::var("PLX_TAMPER").ok().as_deref() == Some("1") {
        tamper_checks(&receipts, &journals);
    }
    let mut builder = ExecutorEnv::builder();
    builder.write(&INC_TAPE_GUEST_ID).unwrap().write(&journals).unwrap();
    for r in &receipts {
        builder.add_assumption(r.clone());
    }
    let env = builder.build().unwrap();
    let t0 = Instant::now();
    let info = prover.prove_with_opts(env, INC_JOIN_GUEST_ELF, &opts).expect("join");
    let join_ms = t0.elapsed().as_millis();
    let receipt = info.receipt;

    let t1 = Instant::now();
    receipt.verify(INC_JOIN_GUEST_ID).expect("verify join");
    let verify_ms = t1.elapsed().as_millis();
    let j = &receipt.journal.bytes;
    let tape_id: Vec<u8> = INC_TAPE_GUEST_ID.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert_eq!(&j[..32], tape_id.as_slice(), "join commits the inc_tape image");
    assert_eq!(&j[32..64], &pre_root.0, "join pre = engine C");
    assert_eq!(&j[64..96], &post_root.0, "join post = engine C'");
    let size = bincode::serialize(&receipt).expect("serialize").len();
    let total: u128 = chunk_ms.iter().sum::<u128>() + join_ms;
    println!(
        "risc0 inc-height: chunks {chunks} x {per} events, steps {steps}, chunk cycles {cycles}, \
         chunk prove {chunk_ms:?} ms, join prove {join_ms} ms (cycles {}), total {total} ms, \
         verify {verify_ms} ms, {size} B",
        info.stats.total_cycles,
    );
}

/// Re-execute the join (with the real chunk receipts attached) on tampered
/// inputs. Swapped / dropped chunks break the root chain; a forged journal has
/// no receipt to resolve its assumption.
fn tamper_checks(receipts: &[Receipt], journals: &[Vec<u8>]) {
    let join = |js: &Vec<Vec<u8>>| {
        let mut b = ExecutorEnv::builder();
        b.write(&INC_TAPE_GUEST_ID).unwrap().write(js).unwrap();
        for r in receipts {
            b.add_assumption(r.clone());
        }
        default_executor().execute(b.build().unwrap(), INC_JOIN_GUEST_ELF)
    };
    assert!(join(&journals.to_vec()).is_ok(), "chained chunks join");
    let mut swapped = journals.to_vec();
    swapped.swap(0, 1);
    assert!(join(&swapped).is_err(), "swapped chunks must not join");
    let mut dropped = journals.to_vec();
    dropped.remove(1);
    assert!(join(&dropped).is_err(), "dropped chunk must not join");
    let mut forged = journals.to_vec();
    let last = forged.len() - 1;
    forged[last][63] ^= 1;
    assert!(join(&forged).is_err(), "forged post root must not join");
    println!("risc0 inc-height tamper: chained ok; swapped, dropped, forged rejected");
}
