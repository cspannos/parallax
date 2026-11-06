//! Guest cycles per hash: software BLAKE3 vs accelerated SHA-256, at the
//! `C'` preimage lengths. Executor measurement only (no proof needed).

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

fn main() {
    let lens: Vec<u32> = env::read();
    let reps: u32 = env::read();
    let mut out: Vec<(u32, u64, u64)> = Vec::new();
    for len in lens {
        let mut msg = vec![7u8; len as usize];
        let c0 = env::cycle_count();
        for i in 0..reps {
            msg[0] = i as u8;
            core::hint::black_box(blake3::hash(&msg));
        }
        let c1 = env::cycle_count();
        for i in 0..reps {
            msg[0] = i as u8;
            core::hint::black_box(Impl::hash_bytes(&msg));
        }
        let c2 = env::cycle_count();
        out.push((len, (c1 - c0) / reps as u64, (c2 - c1) / reps as u64));
    }
    env::commit(&out);
}
