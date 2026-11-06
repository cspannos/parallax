//! Q-PRF-7 native cost: BLAKE3 vs SHA-256 `C'` (same treap, same preimages).
//!
//!   cargo test -p clob --release --test hash_mode_native -- --ignored --nocapture

use std::time::Instant;

use clob::testutil::{btree_engine, churn_tape, load_places};
use clob::{HashedMap, TreapHash};

fn best_of<F: FnMut() -> u128>(n: usize, mut f: F) -> u128 {
    (0..n).map(|_| f()).min().unwrap()
}

#[test]
#[ignore = "timing; run in release"]
fn native_hash_modes() {
    for mode in [TreapHash::Blake3, TreapHash::Sha256] {
        // One-map ops at 8k, 16 B keys, 200 B values.
        let key = |i: u64| -> [u8; 16] { (i.wrapping_mul(0x9E37_79B9_7F4A_7C15) as u128).to_be_bytes() };
        let mut m = HashedMap::with_hash(mode);
        for i in 0..8_000 {
            m.upsert(&key(i), &[1; 200]);
        }
        let n = 2_000u64;
        let ins = best_of(5, || {
            let mut c = m.clone();
            let t = Instant::now();
            for i in 0..n {
                c.upsert(&key(100_000 + i), &[2; 200]);
            }
            t.elapsed().as_nanos() / n as u128
        });
        let upd = best_of(5, || {
            let mut c = m.clone();
            let t = Instant::now();
            for i in 0..n {
                c.upsert(&key(i), &[3; 200]);
            }
            t.elapsed().as_nanos() / n as u128
        });
        let rem = best_of(5, || {
            let mut c = m.clone();
            let t = Instant::now();
            for i in 0..n {
                c.remove(&key(i));
            }
            t.elapsed().as_nanos() / n as u128
        });
        // Engine: loaded 10k mixed tape on an 8k book (treap C' on).
        let mut base = btree_engine();
        base.set_treap_hash(mode);
        base.apply_all(load_places(8_000));
        let tape = churn_tape(8_000, 10_000);
        let f_ms = best_of(5, || {
            let mut e = base.clone();
            let t = Instant::now();
            e.apply_all(tape.clone());
            std::hint::black_box(e.state_root());
            t.elapsed().as_micros()
        });
        eprintln!(
            "native {mode:?} @8k: insert {:.2} µs, update {:.2} µs, remove {:.2} µs; loaded 10k engine apply {:.1} ms",
            ins as f64 / 1e3,
            upd as f64 / 1e3,
            rem as f64 / 1e3,
            f_ms as f64 / 1e3
        );
    }
}
