//! Percentile benches for `BTreeBook` vs `VecBook`.
//!
//! Run: `cargo run -p clob-bench --release`
//! Times are nanoseconds. Matcher benches disable per-apply commitment walks.

use std::time::Instant;

use clob::testutil::{churn_tape, genesis, limit, load_places, oid, owner};
use clob::{take_treap_hash_calls, BTreeBook, Engine, HashedMap, TreapHash, VecBook};
use protocol_types::{Input, Side};
use replica::{Replica, ReplicaOpts};
use storage::SyncMode;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn in_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

fn new_engine<B: clob::Book + Default>(commit: bool) -> Engine<B> {
    let mut e = Engine::<B>::new(genesis());
    e.commit_on_apply = commit;
    e.incremental_on_apply = false;
    e
}

fn pct(sorted: &[u128], permille: u32) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let i = (sorted.len() - 1) * permille as usize / 1000;
    sorted[i]
}

fn report(name: &str, mut ns: Vec<u128>) {
    ns.sort_unstable();
    println!(
        "{name:32} n={:<7} p50={:<10} p95={:<10} p99={:<10} p99.9={:<10} max={}",
        ns.len(),
        pct(&ns, 500),
        pct(&ns, 950),
        pct(&ns, 990),
        pct(&ns, 999),
        ns.last().copied().unwrap_or(0),
    );
}

fn bench_insert<B: clob::Book + Default>(label: &str, n: usize) {
    let mut rng = XorShift(0xC0FFEE);
    let mut samples = Vec::with_capacity(n);
    let mut e = new_engine::<B>(false);
    let mut nonce = 1u64;
    for i in 0..n {
        let price = rng.in_range(1, 10_000);
        let qty = rng.in_range(1, 20);
        let order = limit(i as u128 + 1, 1, Side::Buy, qty, price, nonce);
        nonce += 1;
        let t0 = Instant::now();
        e.apply(Input::Place(order));
        samples.push(t0.elapsed().as_nanos());
    }
    report(&format!("{label}/insert"), samples);
}

fn bench_match<B: clob::Book + Default>(label: &str, n: usize) {
    let mut rng = XorShift(0xBEEF);
    let mut samples = Vec::with_capacity(n);
    let mut e = new_engine::<B>(false);
    for i in 0..n {
        e.apply(Input::Place(limit(
            i as u128 + 1,
            1,
            Side::Sell,
            1,
            rng.in_range(50, 150),
            i as u64 + 1,
        )));
    }
    for i in 0..n {
        let order = limit((n + i) as u128 + 1, 2, Side::Buy, 1, 200, i as u64 + 1);
        let t0 = Instant::now();
        e.apply(Input::Place(order));
        samples.push(t0.elapsed().as_nanos());
    }
    report(&format!("{label}/match"), samples);
}

fn bench_cancel<B: clob::Book + Default>(label: &str, n: usize) {
    let mut e = new_engine::<B>(false);
    for i in 0..n {
        e.apply(Input::Place(limit(
            i as u128 + 1,
            1,
            Side::Buy,
            1,
            10,
            i as u64 + 1,
        )));
    }
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        let t0 = Instant::now();
        e.apply(Input::Cancel {
            order_id: oid(i as u128 + 1),
            owner: owner(1),
            nonce: (n as u64) + i as u64 + 1,
        });
        samples.push(t0.elapsed().as_nanos());
    }
    report(&format!("{label}/cancel"), samples);
}

fn bench_root<B: clob::Book + Default>(label: &str, resting: usize, n: usize) {
    let mut e = new_engine::<B>(false);
    for i in 0..resting {
        e.apply(Input::Place(limit(
            i as u128 + 1,
            1,
            Side::Buy,
            1,
            (i as u64 % 100) + 1,
            i as u64 + 1,
        )));
    }
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let _ = e.full_walk_root();
        samples.push(t0.elapsed().as_nanos());
    }
    report(&format!("{label}/state_root_{resting}"), samples);
}

fn load_resting<B: clob::Book + Default>(commit: bool, inc: bool, resting: usize) -> Engine<B> {
    let mut e = new_engine::<B>(false);
    e.incremental_on_apply = inc;
    for i in 0..resting {
        e.apply(Input::Place(limit(
            i as u128 + 1,
            1,
            Side::Buy,
            1,
            (i as u64 % 100) + 1,
            i as u64 + 1,
        )));
    }
    e.commit_on_apply = commit;
    e
}

fn bench_apply_at_loaded<B: clob::Book + Default>(
    label: &str,
    commit: bool,
    inc: bool,
    resting: usize,
    n: usize,
    kind: &str,
) {
    let mut e = load_resting::<B>(commit, inc, resting);
    let mut samples = Vec::with_capacity(n);
    for s in 0..n {
        let t0 = Instant::now();
        match kind {
            "insert" => {
                e.apply(Input::Place(limit(
                    (resting + s + 1) as u128,
                    1,
                    Side::Buy,
                    1,
                    10_000 + s as u64,
                    (resting + s + 1) as u64,
                )));
            }
            "cancel" => {
                e.apply(Input::Cancel {
                    order_id: oid((s + 1) as u128),
                    owner: owner(1),
                    nonce: (resting + s + 1) as u64,
                });
            }
            _ => panic!("unknown kind"),
        }
        samples.push(t0.elapsed().as_nanos());
    }
    report(&format!("{label}/{kind}_at_{resting}"), samples);
}

fn bench_inc_root<B: clob::Book + Default>(label: &str, resting: usize, n: usize) {
    let e = load_resting::<B>(false, true, resting);
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let _ = e.incremental_root();
        samples.push(t0.elapsed().as_nanos());
    }
    report(&format!("{label}/inc_root_{resting}"), samples);
}

fn main() {
    if std::env::var("CLOB_BENCH_ONLY").ok().as_deref() == Some("batch") {
        run_loaded_batches();
        return;
    }
    if std::env::var("CLOB_BENCH_ONLY").ok().as_deref() == Some("wal") {
        run_wal_batches();
        return;
    }
    if std::env::var("CLOB_BENCH_ONLY").ok().as_deref() == Some("clone") {
        run_clone_isolate();
        return;
    }
    if std::env::var("CLOB_BENCH_ONLY").ok().as_deref() == Some("treap") {
        run_treap_isolate();
        return;
    }

    let n = std::env::var("CLOB_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000usize);
    println!("clob-bench n={n} nanoseconds. Matcher benches have commit_on_apply=false and incremental_on_apply=false.");
    println!(
        "{:32} {:<7} {:<10} {:<10} {:<10} {:<10} {}",
        "bench", "n", "p50", "p95", "p99", "p99.9", "max"
    );

    bench_insert::<BTreeBook>("BTreeBook", n);
    bench_insert::<VecBook>("VecBook", n);
    bench_match::<BTreeBook>("BTreeBook", n);
    bench_match::<VecBook>("VecBook", n);
    bench_cancel::<BTreeBook>("BTreeBook", n);
    bench_cancel::<VecBook>("VecBook", n);
    bench_root::<BTreeBook>("BTreeBook", 1_000, 2_000);
    bench_root::<VecBook>("VecBook", 1_000, 2_000);
    bench_root::<BTreeBook>("BTreeBook", 8_000, 500);
    bench_root::<VecBook>("VecBook", 8_000, 500);

    bench_inc_root::<BTreeBook>("BTreeBook", 1_000, 2_000);
    bench_inc_root::<BTreeBook>("BTreeBook", 8_000, 500);

    // One apply on a loaded book: full Blake3 walk vs incremental treap.
    bench_apply_at_loaded::<BTreeBook>("full_walk", true, false, 8_000, 500, "insert");
    bench_apply_at_loaded::<BTreeBook>("full_walk", true, false, 8_000, 500, "cancel");
    bench_apply_at_loaded::<BTreeBook>("incremental", false, true, 8_000, 500, "insert");
    bench_apply_at_loaded::<BTreeBook>("incremental", false, true, 8_000, 500, "cancel");

    run_loaded_batches();
}

fn report_batch(name: &str, resting: usize, batch: usize, mut ns: Vec<u128>) {
    ns.sort_unstable();
    let p50 = pct(&ns, 500);
    let eps = if p50 == 0 {
        0
    } else {
        (batch as u128).saturating_mul(1_000_000_000) / p50
    };
    println!(
        "{name:40} rest={resting:<6} |I|={batch:<6} n={:<4} p50={:<12} p95={:<12} p99={:<12} max={}  ~{eps} ev/s",
        ns.len(),
        p50,
        pct(&ns, 950),
        pct(&ns, 990),
        ns.last().copied().unwrap_or(0),
    );
}

fn bench_loaded_batch(
    resting: usize,
    batch: usize,
    samples: usize,
    commit: bool,
    inc: bool,
    label: &str,
) {
    let tape = churn_tape(resting, batch);
    let base = load_resting::<BTreeBook>(commit, inc, resting);
    let mut ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut e = base.clone();
        let t0 = Instant::now();
        for input in tape.iter().cloned() {
            let _ = e.apply(input);
        }
        if inc {
            let _ = e.incremental_root();
        }
        ns.push(t0.elapsed().as_nanos());
    }
    report_batch(label, resting, batch, ns);
}

fn run_loaded_batches() {
    println!();
    println!("loaded-batch: mixed I on a loaded BTreeBook. nanoseconds for the whole tape + root.");
    println!(
        "WAL off. Malachite off. match = no commit; inc = treap; walk = full Blake3 receipts."
    );
    println!(
        "{:40} {:<13} {:<11} {:<5} {:<12} {:<12} {:<12} {}  implied",
        "bench", "resting", "|I|", "n", "p50", "p95", "p99", "max"
    );

    // full walk only on the small cell — 10k × ~3 ms/apply is a minutes-long run.
    bench_loaded_batch(8_000, 100, 40, true, false, "walk/batch");
    bench_loaded_batch(8_000, 100, 40, false, false, "match/batch");
    bench_loaded_batch(8_000, 100, 40, false, true, "inc/batch");
    bench_loaded_batch(8_000, 1_000, 20, false, false, "match/batch");
    bench_loaded_batch(8_000, 1_000, 20, false, true, "inc/batch");
    bench_loaded_batch(8_000, 10_000, 10, false, false, "match/batch");
    bench_loaded_batch(8_000, 10_000, 10, false, true, "inc/batch");

    bench_loaded_batch(32_000, 100, 20, false, false, "match/batch");
    bench_loaded_batch(32_000, 100, 20, false, true, "inc/batch");
    bench_loaded_batch(32_000, 1_000, 10, false, false, "match/batch");
    bench_loaded_batch(32_000, 1_000, 10, false, true, "inc/batch");
    bench_loaded_batch(32_000, 10_000, 8, false, false, "match/batch");
    bench_loaded_batch(32_000, 10_000, 8, false, true, "inc/batch");
}

/// Clone vs apply vs `replay` (`clone` + `apply_all`). Incremental `C'` on.
fn bench_clone_only(resting: usize, inc: bool, samples: usize, label: &str) {
    let base = load_resting::<BTreeBook>(false, inc, resting);
    let mut ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t0 = Instant::now();
        let scratch = base.clone();
        std::hint::black_box(&scratch);
        ns.push(t0.elapsed().as_nanos());
    }
    report_batch(label, resting, 0, ns);
}

fn bench_apply_only(resting: usize, batch: usize, samples: usize) {
    let tape = churn_tape(resting, batch);
    let base = load_resting::<BTreeBook>(false, true, resting);
    let mut ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let mut e = base.clone();
        let t0 = Instant::now();
        let _ = e.apply_all(tape.iter().cloned());
        let _ = e.incremental_root();
        ns.push(t0.elapsed().as_nanos());
    }
    report_batch("apply/inc", resting, batch, ns);
}

fn bench_replay(resting: usize, batch: usize, samples: usize) {
    let tape = churn_tape(resting, batch);
    let base = load_resting::<BTreeBook>(false, true, resting);
    let mut ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let t0 = Instant::now();
        let mut scratch = base.clone();
        let _ = scratch.apply_all(tape.iter().cloned());
        let _ = scratch.incremental_root();
        ns.push(t0.elapsed().as_nanos());
    }
    report_batch("replay/clone+apply", resting, batch, ns);
}

fn run_clone_isolate() {
    println!();
    println!("clone-vs-apply: Engine clone vs apply_all vs replay (clone+apply).");
    println!("Incremental C' on unless clone/book. WAL off. Malachite off.");
    println!(
        "{:40} {:<13} {:<11} {:<5} {:<12} {:<12} {:<12} {}  implied",
        "bench", "resting", "|I|", "n", "p50", "p95", "p99", "max"
    );

    bench_clone_only(8_000, true, 40, "clone/inc");
    bench_clone_only(32_000, true, 20, "clone/inc");
    bench_clone_only(8_000, false, 40, "clone/book");
    bench_clone_only(32_000, false, 20, "clone/book");

    bench_apply_only(8_000, 10_000, 10);
    bench_apply_only(32_000, 10_000, 8);

    bench_replay(8_000, 10_000, 10);
    bench_replay(32_000, 10_000, 8);
}

fn map_key(i: usize) -> [u8; 8] {
    (i as u64).to_le_bytes()
}

fn fill_map(hash: TreapHash, n: usize) -> HashedMap {
    let mut m = HashedMap::with_hash(hash);
    let val = [0u8; 32];
    for i in 0..n {
        m.upsert(&map_key(i), &val);
    }
    m
}

fn bench_map_upsert(label: &str, hash: TreapHash, resting: usize, n: usize) {
    let mut m = fill_map(hash, resting);
    let val = [0u8; 32];
    let mut samples = Vec::with_capacity(n);
    for s in 0..n {
        let t0 = Instant::now();
        m.upsert(&map_key(resting + s), &val);
        samples.push(t0.elapsed().as_nanos());
    }
    report(label, samples);
}

fn bench_alloc_only(resting: usize, n: usize) {
    struct Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
    }
    let mut v: Vec<Box<Leaf>> = Vec::with_capacity(resting + n);
    for i in 0..resting {
        v.push(Box::new(Leaf {
            key: map_key(i).to_vec(),
            value: vec![0; 32],
        }));
    }
    let mut samples = Vec::with_capacity(n);
    for s in 0..n {
        let t0 = Instant::now();
        v.push(Box::new(Leaf {
            key: map_key(resting + s).to_vec(),
            value: vec![0; 32],
        }));
        std::hint::black_box((&v.last().unwrap().key, &v.last().unwrap().value));
        samples.push(t0.elapsed().as_nanos());
    }
    report("alloc/leaf_at_8000", samples);
}

fn load_resting_hash(inc: bool, hash: TreapHash, resting: usize) -> Engine<BTreeBook> {
    let mut e = new_engine::<BTreeBook>(false);
    e.incremental_on_apply = inc;
    if inc {
        e.set_treap_hash(hash);
    }
    for i in 0..resting {
        e.apply(Input::Place(limit(
            i as u128 + 1,
            1,
            Side::Buy,
            1,
            (i as u64 % 100) + 1,
            i as u64 + 1,
        )));
    }
    e
}

fn bench_engine_insert(label: &str, inc: bool, hash: TreapHash, resting: usize, n: usize) {
    let mut e = load_resting_hash(inc, hash, resting);
    let mut samples = Vec::with_capacity(n);
    for s in 0..n {
        let t0 = Instant::now();
        e.apply(Input::Place(limit(
            (resting + s + 1) as u128,
            1,
            Side::Buy,
            1,
            10_000 + s as u64,
            (resting + s + 1) as u64,
        )));
        samples.push(t0.elapsed().as_nanos());
    }
    report(label, samples);
}

fn run_treap_isolate() {
    println!();
    println!("treap isolate: SHA-256 (production) and BLAKE3 v1 vs split/merge vs alloc. 8k insert cell.");
    println!("NopRehash keeps the production (SHA-256) priority (same shape); skips node_digest.");
    println!("WAL off. Malachite off. nanoseconds.");
    println!(
        "{:32} {:<7} {:<10} {:<10} {:<10} {:<10} {}",
        "bench", "n", "p50", "p95", "p99", "p99.9", "max"
    );

    let mut counted = fill_map(TreapHash::Blake3Count, 8_000);
    let _ = take_treap_hash_calls();
    counted.upsert(&map_key(8_000), &[0u8; 32]);
    let calls = take_treap_hash_calls();
    println!(
        "blake3_count/upsert_at_8000         prio={} node={} empty_blake3={} empty_lookup={} blake3={}",
        calls.prio, calls.node, calls.empty_compute, calls.empty_lookup, calls.blake3()
    );

    bench_map_upsert("map/sha256_at_8000", TreapHash::Sha256, 8_000, 500);
    bench_map_upsert("map/blake3_v1_at_8000", TreapHash::Blake3, 8_000, 500);
    bench_map_upsert("map/nop_rehash_at_8000", TreapHash::NopRehash, 8_000, 500);
    bench_alloc_only(8_000, 500);

    bench_engine_insert(
        "engine/sha256_insert_8k",
        true,
        TreapHash::Sha256,
        8_000,
        500,
    );
    bench_engine_insert(
        "engine/blake3_v1_insert_8k",
        true,
        TreapHash::Blake3,
        8_000,
        500,
    );
    bench_engine_insert(
        "engine/nop_rehash_insert_8k",
        true,
        TreapHash::NopRehash,
        8_000,
        500,
    );
    bench_engine_insert(
        "engine/match_insert_8k",
        false,
        TreapHash::Blake3,
        8_000,
        500,
    );
}

#[derive(Clone, Copy)]
enum WalDurability {
    /// Flush only (today's Relaxed).
    Relaxed,
    /// `sync_all` after every record (M2 / ADR 0007).
    Full,
    /// Flush each record, one `sync_all` after the tape (ADR 0012).
    Height,
}

fn open_loaded_replica(preload: &[Input]) -> (tempfile::TempDir, Replica) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("replica.wal");
    let mut opts = ReplicaOpts::new(&path, [7u8; 32], genesis());
    opts.sync = SyncMode::Relaxed;
    let (mut replica, _) = Replica::open(opts).expect("open replica");
    replica.engine_mut().commit_on_apply = false;
    replica.engine_mut().incremental_on_apply = true;
    replica
        .submit_batch(preload.iter().cloned())
        .expect("preload");
    (dir, replica)
}

fn bench_wal_tape(durability: WalDurability, resting: usize, batch: usize, samples: usize) {
    let tape = churn_tape(resting, batch);
    let preload = load_places(resting);
    let label = match durability {
        WalDurability::Relaxed => "wal/relaxed",
        WalDurability::Full => "wal/full",
        WalDurability::Height => "wal/height",
    };
    let mut ns = Vec::with_capacity(samples);
    for _ in 0..samples {
        let (_dir, mut replica) = open_loaded_replica(&preload);
        match durability {
            WalDurability::Full => replica.set_sync(SyncMode::Full),
            WalDurability::Relaxed => replica.set_sync(SyncMode::Relaxed),
            WalDurability::Height => replica.set_sync(SyncMode::Height),
        }
        let t0 = Instant::now();
        replica.submit_batch(tape.iter().cloned()).expect("submit");
        let _ = replica.engine().incremental_root();
        ns.push(t0.elapsed().as_nanos());
    }
    report_batch(label, resting, batch, ns);
}

fn run_wal_batches() {
    println!();
    println!("wal-batch: mixed I, incremental CLOB, replica WAL then apply. Malachite off.");
    println!("relaxed = flush; full = sync_all per record; height = one sync_all after |I|.");
    println!(
        "{:40} {:<13} {:<11} {:<5} {:<12} {:<12} {:<12} {}  implied",
        "bench", "resting", "|I|", "n", "p50", "p95", "p99", "max"
    );

    bench_wal_tape(WalDurability::Relaxed, 8_000, 100, 20);
    bench_wal_tape(WalDurability::Height, 8_000, 100, 20);
    bench_wal_tape(WalDurability::Full, 8_000, 100, 16);

    bench_wal_tape(WalDurability::Relaxed, 8_000, 1_000, 10);
    bench_wal_tape(WalDurability::Height, 8_000, 1_000, 10);
    bench_wal_tape(WalDurability::Full, 8_000, 1_000, 8);

    bench_wal_tape(WalDurability::Relaxed, 8_000, 10_000, 6);
    bench_wal_tape(WalDurability::Height, 8_000, 10_000, 6);
    bench_wal_tape(WalDurability::Full, 8_000, 10_000, 3);

    bench_wal_tape(WalDurability::Relaxed, 32_000, 100, 10);
    bench_wal_tape(WalDurability::Height, 32_000, 100, 10);
    bench_wal_tape(WalDurability::Full, 32_000, 100, 8);

    bench_wal_tape(WalDurability::Relaxed, 32_000, 1_000, 6);
    bench_wal_tape(WalDurability::Height, 32_000, 1_000, 6);
    bench_wal_tape(WalDurability::Full, 32_000, 1_000, 4);

    bench_wal_tape(WalDurability::Relaxed, 32_000, 10_000, 4);
    bench_wal_tape(WalDurability::Height, 32_000, 10_000, 4);
    bench_wal_tape(WalDurability::Full, 32_000, 10_000, 3);
}
