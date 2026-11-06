use risc0_zkvm::guest::env;
use tiny_f_guest_logic::{
    book_step, BENCH_R0P, BENCH_R0Q, BENCH_R1P, BENCH_R1Q, BENCH_TP, BENCH_TQ,
};

fn main() {
    let r0q: u64 = env::read();
    let r0p: u64 = env::read();
    let r1q: u64 = env::read();
    let r1p: u64 = env::read();
    let tq: u64 = env::read();
    let tp: u64 = env::read();
    assert_eq!(
        (r0q, r0p, r1q, r1p, tq, tp),
        (BENCH_R0Q, BENCH_R0P, BENCH_R1Q, BENCH_R1P, BENCH_TQ, BENCH_TP)
    );
    let out = book_step(r0q, r0p, r1q, r1p, tq, tp).expect("instance class");
    env::commit(&(out.fill0, out.fill1, out.take_left, out.n0, out.n1));
}
