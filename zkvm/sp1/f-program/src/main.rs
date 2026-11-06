//! `π` of `F` on SP1 (ADR 0025 comparison): same statement as the RISC Zero
//! `f_guest`. Input: `u32 snapshot_len ‖ snapshot ‖ commit_list_payload(I)`.
//! Public values: the 129-byte `FClaim`. SHA-256 goes through SP1's patched
//! `sha2` (precompile).
#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let n = u32::from_le_bytes(bytes[..4].try_into().expect("len")) as usize;
    let (snapshot, inputs) = bytes[4..].split_at(n);
    let claim = clob::run_f(snapshot, inputs).expect("F");
    sp1_zkvm::io::commit_slice(&claim.to_bytes());
}
