//! Aggregate chunk receipts of the `inc_tape` guest into one claim (B4).
//!
//! Verifies each chunk journal under `tape_id` (recursion via assumptions),
//! requires chunk `i` post root = chunk `i+1` pre root, and commits
//! `tape_id ‖ first pre ‖ last post ‖ ops ‖ steps ‖ chunks`. The verifier must
//! check `tape_id` is the `inc_tape` image. Not `F`.

use risc0_zkvm::guest::env;

const OPS_JOIN_DOMAIN: &[u8] = b"plx/clob/inc-ops-join/v1";

fn main() {
    let tape_id: [u32; 8] = env::read();
    let journals: Vec<Vec<u8>> = env::read();
    assert!(!journals.is_empty(), "no chunks");
    let mut ops = blake3::Hasher::new();
    ops.update(OPS_JOIN_DOMAIN);
    ops.update(&(journals.len() as u64).to_le_bytes());
    let mut steps = 0u64;
    for (i, j) in journals.iter().enumerate() {
        assert_eq!(j.len(), 100, "chunk journal");
        env::verify(tape_id, j.as_slice()).expect("chunk receipt");
        if i > 0 {
            assert_eq!(&journals[i - 1][32..64], &j[..32], "chunk roots chain");
        }
        ops.update(&j[64..96]);
        steps += u32::from_le_bytes(j[96..100].try_into().unwrap()) as u64;
    }
    let mut out = Vec::with_capacity(32 + 32 * 3 + 16);
    for w in tape_id {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(&journals[0][..32]);
    out.extend_from_slice(&journals[journals.len() - 1][32..64]);
    out.extend_from_slice(ops.finalize().as_bytes());
    out.extend_from_slice(&steps.to_le_bytes());
    out.extend_from_slice(&(journals.len() as u64).to_le_bytes());
    env::commit_slice(&out);
}
