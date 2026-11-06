//! Hasher for the books' `OrderId` index (ADR 0032).
//!
//! - **Natively** (validators, followers): keyed SipHash (`RandomState`).
//!   Order ids are `H(owner, nonce)`, cheap for an attacker to grind, so an
//!   unkeyed index hash would let them pile orders into one bucket and slow
//!   every lookup on every validator.
//! - **In the zkVM guest** (`target_os = "zkvm"`): an unkeyed multiply-xor
//!   fold. SipHash cost ~22 M cycles per 10k-event `π`; by the time a height
//!   is proven its `I` is fixed, so grinding only costs the prover time.
//!
//! Iteration order of the index is never used, so the choice cannot change a
//! root or a receipt.

use std::hash::Hasher;

#[derive(Default)]
pub struct IdHasher(u64);

impl Hasher for IdHasher {
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut w = [0u8; 8];
            w[..chunk.len()].copy_from_slice(chunk);
            self.0 = (self.0.rotate_left(5) ^ u64::from_le_bytes(w)).wrapping_mul(0x517c_c1b7_2722_0a95);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

#[cfg(target_os = "zkvm")]
pub type IdHashBuilder = std::hash::BuildHasherDefault<IdHasher>;
#[cfg(not(target_os = "zkvm"))]
pub type IdHashBuilder = std::collections::hash_map::RandomState;
