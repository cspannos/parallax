//! Guest-safe copy of `crates/tiny-f` fragments. Keep in lockstep.
//!
//! Not the CLOB. Not an 8k book. Not height π.

pub const QTY_BITS: u32 = 15;
pub const MAX_LIMB: u64 = (1 << QTY_BITS) - 1;

/// Instance used in M6a benches (matches Plonky3 / CLOB two-order cross).
pub const BENCH_MAKER: u64 = 10;
pub const BENCH_TAKER: u64 = 7;
pub const BENCH_PRICE: u64 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TinyOut {
    pub fill_qty: u64,
    pub notional: u128,
}

pub fn tiny_f(maker_qty: u64, taker_qty: u64, price: u64) -> Result<TinyOut, ()> {
    if maker_qty > MAX_LIMB || taker_qty > MAX_LIMB || price > MAX_LIMB {
        return Err(());
    }
    let fill_qty = maker_qty.min(taker_qty);
    Ok(TinyOut {
        fill_qty,
        notional: u128::from(fill_qty) * u128::from(price),
    })
}

pub fn bench_instance() -> TinyOut {
    tiny_f(BENCH_MAKER, BENCH_TAKER, BENCH_PRICE).expect("bench instance in class")
}

/// Two-ask walk used in the Plonky3 book-step cell (5@80 + 10@90, take 12@100).
pub const BENCH_R0Q: u64 = 5;
pub const BENCH_R0P: u64 = 80;
pub const BENCH_R1Q: u64 = 10;
pub const BENCH_R1P: u64 = 90;
pub const BENCH_TQ: u64 = 12;
pub const BENCH_TP: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookOut {
    pub fill0: u64,
    pub rem0: u64,
    pub n0: u128,
    pub fill1: u64,
    pub rem1: u64,
    pub n1: u128,
    pub take_left: u64,
}

fn match_level(rest_q: u64, rest_p: u64, take_q: u64, take_p: u64) -> Result<(u64, u64, u128), ()> {
    if rest_q > MAX_LIMB || rest_p > MAX_LIMB || take_q > MAX_LIMB || take_p > MAX_LIMB {
        return Err(());
    }
    let fill = if take_p >= rest_p {
        rest_q.min(take_q)
    } else {
        0
    };
    Ok((fill, rest_q - fill, u128::from(fill) * u128::from(rest_p)))
}

pub fn book_step(
    r0q: u64,
    r0p: u64,
    r1q: u64,
    r1p: u64,
    tq: u64,
    tp: u64,
) -> Result<BookOut, ()> {
    if r0p > r1p {
        return Err(());
    }
    let (fill0, rem0, n0) = match_level(r0q, r0p, tq, tp)?;
    let take_after = tq - fill0;
    let (fill1, rem1, n1) = match_level(r1q, r1p, take_after, tp)?;
    Ok(BookOut {
        fill0,
        rem0,
        n0,
        fill1,
        rem1,
        n1,
        take_left: take_after - fill1,
    })
}

pub fn bench_book() -> BookOut {
    book_step(
        BENCH_R0Q, BENCH_R0P, BENCH_R1Q, BENCH_R1P, BENCH_TQ, BENCH_TP,
    )
    .expect("bench book in class")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_is_fill_7_notional_630() {
        let o = bench_instance();
        assert_eq!(o.fill_qty, 7);
        assert_eq!(o.notional, 630);
    }

    #[test]
    fn bench_book_walks_two_asks() {
        let o = bench_book();
        assert_eq!(o.fill0, 5);
        assert_eq!(o.n0, 400);
        assert_eq!(o.fill1, 7);
        assert_eq!(o.n1, 630);
        assert_eq!(o.take_left, 0);
    }
}
