//! Cycles per hash in the RISC Zero guest: BLAKE3 (software) vs SHA-256
//! (accelerator), at `C'` preimage lengths. Executor only.
//!
//!   RISC0_DEV_MODE=0 cargo run --release -p host --bin hashbench

use methods::HASHBENCH_GUEST_ELF;
use risc0_zkvm::{default_executor, ExecutorEnv};

fn main() {
    let lens: Vec<u32> = vec![33, 49, 115, 139, 216];
    let env = ExecutorEnv::builder().write(&lens).unwrap().write(&64u32).unwrap().build().unwrap();
    let session = default_executor().execute(env, HASHBENCH_GUEST_ELF).expect("execute");
    let rows: Vec<(u32, u64, u64)> = session.journal.decode().expect("journal");
    for (len, b3, sha) in rows {
        println!("risc0 guest hash {len} B: blake3 {b3} cycles, sha256 {sha} cycles");
    }
}
