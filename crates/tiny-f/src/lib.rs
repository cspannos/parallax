//! Tiny transition `F` for M6: one crossing fill (ADR 0011).
//!
//! [`match_step`] is one sell rest + one buy take. [`book_step`] walks two
//! asks. [`book_walk`] walks k asks. [`mixed_f`] is rest/take/cancel on eight
//! slots. [`scan_event`] is one mixed event on a packed prefix (an 8k book
//! as rows). Still 15-bit. This is **not** `C'` and **not** a license to
//! apply a height’s `SettlementDelta` list.
#![forbid(unsafe_code)]

mod book_step;
mod book_walk;
mod match_step;
mod mixed;
mod scan;

pub use book_step::{book_step, BookLevel, BookStepInstance, BookStepOutput, BookStepStatement};
pub use book_walk::{
    book_walk, pad_walk, unit_asks, BookWalkInstance, BookWalkOutput, BookWalkStatement,
};
pub use match_step::{match_step, MatchStepInstance, MatchStepOutput, MatchStepStatement};
pub use mixed::{
    mixed_f, unit_mixed, MixEvent, MixKind, MixedEventOut, MixedInstance, MixedOutput,
    MixedStatement, MIX_SLOTS,
};
pub use scan::{
    apply_scan_tape, scan_event, unit_scan_book, unit_scan_tape, ScanInstance, ScanOutput,
    ScanStatement,
};

use protocol_types::{notional, CanonicalEncode, EncodeBuf, Price, Qty};

/// AIR range-check width. Values above this are outside the M6a instance class
/// (product must fit in BabyBear ≈ 2^31).
pub const QTY_BITS: u32 = 15;
pub const MAX_LIMB: u64 = (1 << QTY_BITS) - 1;
/// Mixed-`I` notional accumulator. Per-event notionals stay 15-bit; the
/// running sum is O(k²) and needs this many bits at k=8192.
pub const MIX_NOTIONAL_BITS: u32 = 24;
pub const MAX_MIX_NOTIONAL: u128 = (1 << MIX_NOTIONAL_BITS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TinyInstance {
    /// Resting maker remaining quantity.
    pub maker_qty: Qty,
    /// Incoming taker remaining quantity.
    pub taker_qty: Qty,
    /// Maker limit_v1 (CLOB fills at maker price).
    pub price: Price,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TinyOutput {
    pub fill_qty: Qty,
    pub notional: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TinyStatement {
    pub instance: TinyInstance,
    pub output: TinyOutput,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TinyFError {
    #[error("qty or price exceeds 15-bit M6a instance class")]
    OutsideInstanceClass,
    #[error("output does not match native tiny_f")]
    OutputMismatch,
}

/// Native spec: `fill = min(maker, taker)`, `notional = fill × price` (ADR 0006).
pub fn tiny_f(instance: TinyInstance) -> Result<TinyOutput, TinyFError> {
    if instance.maker_qty.0 > MAX_LIMB
        || instance.taker_qty.0 > MAX_LIMB
        || instance.price.0 > MAX_LIMB
    {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let fill_qty = instance.maker_qty.saturating_min(instance.taker_qty);
    Ok(TinyOutput {
        fill_qty,
        notional: notional(fill_qty, instance.price),
    })
}

impl TinyStatement {
    pub fn prove_native(instance: TinyInstance) -> Result<Self, TinyFError> {
        let output = tiny_f(instance)?;
        Ok(Self { instance, output })
    }

    pub fn check(&self) -> Result<(), TinyFError> {
        let expected = tiny_f(self.instance)?;
        if expected == self.output {
            Ok(())
        } else {
            Err(TinyFError::OutputMismatch)
        }
    }
}

impl CanonicalEncode for TinyInstance {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"TNYINST\0");
        self.maker_qty.encode(buf);
        self.taker_qty.encode(buf);
        self.price.encode(buf);
    }
}

impl CanonicalEncode for TinyOutput {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"TNYOUT\0\0");
        self.fill_qty.encode(buf);
        buf.u128(self.notional);
    }
}

impl CanonicalEncode for TinyStatement {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"TNYSTMT\0");
        self.instance.encode(buf);
        self.output.encode(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine_v1, limit_v1};
    use protocol_types::{Input, Side};

    #[test]
    fn min_and_notional_match_clob_maker_price() {
        let mut engine = btree_engine_v1();
        let _ = engine.apply(Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)));
        let r = engine.apply(Input::Place(limit_v1(2, 2, Side::Buy, 7, 100, 1)));
        assert_eq!(r.fills.len(), 1);
        let f = &r.fills[0];
        let stmt = TinyStatement::prove_native(TinyInstance {
            maker_qty: Qty(10),
            taker_qty: Qty(7),
            price: Price(90),
        })
        .unwrap();
        assert_eq!(stmt.output.fill_qty, f.qty);
        assert_eq!(stmt.output.notional, notional(f.qty, f.price));
        assert_eq!(f.price, Price(90), "CLOB fills at maker price");
    }

    #[test]
    fn equal_qty_full_fill() {
        let stmt = TinyStatement::prove_native(TinyInstance {
            maker_qty: Qty(10),
            taker_qty: Qty(10),
            price: Price(90),
        })
        .unwrap();
        assert_eq!(stmt.output.fill_qty, Qty(10));
        assert_eq!(stmt.output.notional, 900);
    }

    #[test]
    fn rejects_outside_instance_class() {
        let err = tiny_f(TinyInstance {
            maker_qty: Qty(MAX_LIMB + 1),
            taker_qty: Qty(1),
            price: Price(1),
        });
        assert_eq!(err, Err(TinyFError::OutsideInstanceClass));
    }

    #[test]
    fn zkvm_guest_logic_matches_native() {
        let g = tiny_f_guest_logic::bench_instance();
        let n = TinyStatement::prove_native(TinyInstance {
            maker_qty: Qty(tiny_f_guest_logic::BENCH_MAKER),
            taker_qty: Qty(tiny_f_guest_logic::BENCH_TAKER),
            price: Price(tiny_f_guest_logic::BENCH_PRICE),
        })
        .unwrap();
        assert_eq!(g.fill_qty, n.output.fill_qty.0);
        assert_eq!(g.notional, n.output.notional);
    }

    #[test]
    fn zkvm_book_matches_native() {
        let g = tiny_f_guest_logic::bench_book();
        let n = crate::BookStepStatement::prove_native(crate::BookStepInstance {
            rest0_qty: Qty(tiny_f_guest_logic::BENCH_R0Q),
            rest0_price: Price(tiny_f_guest_logic::BENCH_R0P),
            rest1_qty: Qty(tiny_f_guest_logic::BENCH_R1Q),
            rest1_price: Price(tiny_f_guest_logic::BENCH_R1P),
            take_qty: Qty(tiny_f_guest_logic::BENCH_TQ),
            take_price: Price(tiny_f_guest_logic::BENCH_TP),
        })
        .unwrap();
        assert_eq!(g.fill0, n.output.level0.fill_qty.0);
        assert_eq!(g.n0, n.output.level0.notional);
        assert_eq!(g.fill1, n.output.level1.fill_qty.0);
        assert_eq!(g.n1, n.output.level1.notional);
        assert_eq!(g.take_left, n.output.take_left.0);
    }
}
