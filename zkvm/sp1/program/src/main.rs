#![no_main]
sp1_zkvm::entrypoint!(main);

use tiny_f_guest_logic::{
    book_step, BENCH_R0P, BENCH_R0Q, BENCH_R1P, BENCH_R1Q, BENCH_TP, BENCH_TQ,
};

pub fn main() {
    let r0q = sp1_zkvm::io::read::<u64>();
    let r0p = sp1_zkvm::io::read::<u64>();
    let r1q = sp1_zkvm::io::read::<u64>();
    let r1p = sp1_zkvm::io::read::<u64>();
    let tq = sp1_zkvm::io::read::<u64>();
    let tp = sp1_zkvm::io::read::<u64>();
    assert_eq!(
        (r0q, r0p, r1q, r1p, tq, tp),
        (BENCH_R0Q, BENCH_R0P, BENCH_R1Q, BENCH_R1P, BENCH_TQ, BENCH_TP)
    );
    let out = book_step(r0q, r0p, r1q, r1p, tq, tp).expect("instance class");
    sp1_zkvm::io::commit(&out.fill0);
    sp1_zkvm::io::commit(&out.fill1);
    sp1_zkvm::io::commit(&out.take_left);
    sp1_zkvm::io::commit(&out.n0);
    sp1_zkvm::io::commit(&out.n1);
}
