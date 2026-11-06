//! General `C'` update: verify an [`IncTape`] of treap steps (ADR 0022) and
//! commit `pre_root ‖ post_root ‖ ops ‖ steps`. Any book, any op mix. Not `F`:
//! the op list is committed, not derived from `I`.

use std::io::Read;

use commitments::IncTape;
use risc0_zkvm::guest::env;

fn main() {
    let mut bytes = Vec::new();
    env::stdin().read_to_end(&mut bytes).expect("tape bytes");
    let tape = IncTape::decode(&bytes).expect("decode tape");
    let claim = tape.verify().expect("valid tape");
    let mut journal = Vec::with_capacity(100);
    journal.extend_from_slice(&claim.pre_root.0);
    journal.extend_from_slice(&claim.post_root.0);
    journal.extend_from_slice(&claim.ops.0);
    journal.extend_from_slice(&(claim.steps as u32).to_le_bytes());
    env::commit_slice(&journal);
}
