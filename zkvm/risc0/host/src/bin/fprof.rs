//! Cycle profile of the `π` of `F` rebuild (executor only).
//!
//!   RISC0_DEV_MODE=0 PLX_F_REST=8000 cargo run --release -p host --bin fprof

use clob::testutil::{btree_engine, load_places};
use methods::FPROF_GUEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};

fn main() {
    let rest: usize = std::env::var("PLX_F_REST").ok().map_or(8_000, |v| v.parse().unwrap());
    let mut e = btree_engine();
    e.apply_all(load_places(rest));
    let snapshot = e.snapshot().encode();
    let mut bytes = (snapshot.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&snapshot);
    let env = ExecutorEnv::builder().write_slice(&bytes).build().unwrap();
    let s = default_executor().execute(env, FPROF_GUEST_ELF).expect("execute");
    let marks: Vec<(String, u64)> = s.journal.decode().unwrap();
    println!("fprof rest {rest} (snapshot {} B), total cycles {}:", snapshot.len(), s.cycles());
    for (name, c) in marks {
        println!("  {c:>12}  {name}");
    }
}
