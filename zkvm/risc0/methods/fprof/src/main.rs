//! Cycle profile of the `π` of `F` rebuild (not a statement; measurement only).
//! Same input as `f_guest`. Commits `(phase, cycles)` pairs.

use std::io::Read;

use clob::{BTreeBook, Book, Engine, EngineSnapshot, HashedMap};
use risc0_zkvm::guest::env;

fn main() {
    commitments::set_sha256_impl(risc0_sha256);
    let mut marks: Vec<(String, u64)> = Vec::new();
    let mut last = env::cycle_count();
    let mut mark = |name: &str, marks: &mut Vec<(String, u64)>| {
        let now = env::cycle_count();
        marks.push((name.to_string(), now - last));
        last = now;
    };
    let mut bytes = Vec::new();
    env::stdin().read_to_end(&mut bytes).expect("input");
    mark("read input", &mut marks);
    let n = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let snap = EngineSnapshot::decode(&bytes[4..4 + n]).expect("decode");
    mark("decode snapshot", &mut marks);
    snap.validate().expect("validate");
    mark("validate (incl. id sort)", &mut marks);
    let mut book = BTreeBook::default();
    book.reserve(snap.resting.len());
    for o in &snap.resting {
        book.insert(o.clone());
    }
    mark("book inserts (reserved)", &mut marks);
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> =
        snap.resting.iter().map(|o| (o.id.0.to_vec(), o.leaf_bytes())).collect();
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    mark("leaf encode + sort (isolated)", &mut marks);
    let m = HashedMap::from_sorted(snap.hash, entries);
    mark("from_sorted resting (isolated)", &mut marks);
    core::hint::black_box(m.root());
    drop(m);
    drop(book);
    mark("drops", &mut marks);
    let mut acc = 0u64;
    for o in &snap.resting {
        acc ^= commitments::priority_u64_with(snap.hash, &o.id.0);
    }
    core::hint::black_box(acc);
    mark("8k x priority_u64_with (SHA 33 B)", &mut marks);
    let z = commitments::Digest([7; 32]);
    let leaf = snap.resting[0].leaf_bytes();
    let mut d = z;
    for o in &snap.resting {
        d = commitments::treap_node_hash_with(snap.hash, &d, &o.id.0, &leaf, &z);
    }
    core::hint::black_box(d);
    mark("8k x treap_node_hash_with (SHA 216 B)", &mut marks);
    let e = Engine::<BTreeBook>::from_snapshot(&snap).expect("from_snapshot");
    mark("Engine::from_snapshot (real path)", &mut marks);
    core::hint::black_box(e.state_root());
    mark("state_root", &mut marks);
    env::commit(&marks);
}

/// RISC Zero's one-call SHA-256 accelerator for production `C'` (standard
/// SHA-256; the host checks the journal against the native statement).
fn risc0_sha256(bytes: &[u8]) -> [u8; 32] {
    use risc0_zkvm::sha::{Impl, Sha256};
    Impl::hash_bytes(bytes).as_bytes().try_into().expect("32 bytes")
}
