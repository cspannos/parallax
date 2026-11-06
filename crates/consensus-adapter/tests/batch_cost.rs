//! Where per-input time goes on a large height (one thread, one replica).
//! `cargo test -p consensus-adapter --release --test batch_cost -- --ignored --nocapture`

use std::time::Instant;

use clob::testutil::{btree_engine, churn_tape, load_places};
use consensus_adapter::{commit_list, height_statement, IntentLog, INPUT_DOMAIN};
use protocol_types::{CanonicalEncode, ConsensusValue, Height};

#[test]
#[ignore]
fn per_input_costs_at_large_heights() {
    for n in [10_000usize, 100_000] {
        let tape = churn_tape(8_000, n);
        let mut base = btree_engine();
        base.apply_all(load_places(8_000));

        let t = Instant::now();
        let mut log = IntentLog::from_batch(Some(tape.clone()));
        let offer = t.elapsed();
        let t = Instant::now();
        let sealed = log.tape(1).unwrap().to_vec();
        let seal = t.elapsed();
        let t = Instant::now();
        let _c = commit_list(&sealed, INPUT_DOMAIN);
        let commit = t.elapsed();
        let t = Instant::now();
        let enc: usize = sealed.iter().map(|i| i.encode_vec().len()).sum();
        let encode = t.elapsed();
        let t = Instant::now();
        let mut scratch = base.clone();
        let clone = t.elapsed();
        scratch.commit_on_apply = false;
        let t = Instant::now();
        let _ = scratch.apply_all(sealed.iter().cloned());
        let _ = scratch.state_root();
        let f = t.elapsed();
        let t = Instant::now();
        let _ = height_statement(&base, ConsensusValue::GENESIS_PARENT, Height(1), &sealed);
        let stmt = t.elapsed();
        let us = |d: std::time::Duration| d.as_secs_f64() * 1e6 / n as f64;
        println!(
            "n={n}: offer {:.2} µs/in, seal {:.2}, commit_list {:.2}, encode {:.2} ({} B/in), engine clone {:.1} ms, F+root {:.2}, height_statement (clone+F+commits) {:.2}",
            us(offer), us(seal), us(commit), us(encode), enc / n, clone.as_secs_f64() * 1e3, us(f), us(stmt)
        );
    }
}
