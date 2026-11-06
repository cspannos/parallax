//! `π` of `F` (ADR 0025): rebuild the engine from a canonical snapshot, commit
//! its `C`, run the real matcher on `I`, and commit
//! `mode ‖ pre_root ‖ post_root ‖ input_commitment ‖ settlement_commitment`.
//! Input: `u32 snapshot_len ‖ snapshot ‖ commit_list_payload(I)`.

use std::io::Read;

use risc0_zkvm::guest::env;

fn main() {
    commitments::set_sha256_impl(risc0_sha256);
    let mut bytes = Vec::new();
    env::stdin().read_to_end(&mut bytes).expect("input");
    let n = u32::from_le_bytes(bytes[..4].try_into().expect("len")) as usize;
    let (snapshot, inputs) = bytes[4..].split_at(n);
    let claim = clob::run_f(snapshot, inputs).expect("F");
    env::commit_slice(&claim.to_bytes());
}

/// RISC Zero's one-call SHA-256 accelerator for production `C'` (standard
/// SHA-256; the host checks the journal against the native statement).
fn risc0_sha256(bytes: &[u8]) -> [u8; 32] {
    use risc0_zkvm::sha::{Impl, Sha256};
    Impl::hash_bytes(bytes).as_bytes().try_into().expect("32 bytes")
}
