//! k sell rests + one buy take. Still 15-bit. Still not `C'`, not an 8k book.
//!
//! Prices are non-decreasing so rest[0] is best (FIFO at a tie). Pad dummy
//! zero-qty asks to a power of two for the AIR.

use protocol_types::{CanonicalEncode, EncodeBuf, Price, Qty};

use crate::match_step::{match_step, MatchStepInstance};
use crate::{BookLevel, TinyFError, MAX_LIMB};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookWalkInstance {
    pub rests: Vec<(Qty, Price)>,
    pub take_qty: Qty,
    pub take_price: Price,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookWalkOutput {
    pub levels: Vec<BookLevel>,
    pub take_left: Qty,
    pub fill_sum: Qty,
    pub notional_sum: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookWalkStatement {
    pub instance: BookWalkInstance,
    pub output: BookWalkOutput,
}

pub fn book_walk(instance: BookWalkInstance) -> Result<BookWalkOutput, TinyFError> {
    if instance.rests.is_empty()
        || instance.take_qty.0 > MAX_LIMB
        || instance.take_price.0 > MAX_LIMB
    {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let mut prev_p = 0u64;
    for (q, p) in &instance.rests {
        if q.0 > MAX_LIMB || p.0 > MAX_LIMB || p.0 < prev_p {
            return Err(TinyFError::OutsideInstanceClass);
        }
        prev_p = p.0;
    }
    let mut take = instance.take_qty;
    let mut levels = Vec::with_capacity(instance.rests.len());
    let mut fill_sum = 0u64;
    let mut notional_sum = 0u128;
    for &(rest_qty, rest_price) in &instance.rests {
        let step = match_step(MatchStepInstance {
            rest_qty,
            rest_price,
            take_qty: take,
            take_price: instance.take_price,
        })?;
        take = Qty(take.0 - step.fill_qty.0);
        fill_sum += step.fill_qty.0;
        notional_sum += step.notional;
        levels.push(BookLevel {
            crosses: step.crosses,
            fill_qty: step.fill_qty,
            remainder: step.remainder,
            notional: step.notional,
        });
    }
    if fill_sum > MAX_LIMB || notional_sum > u128::from(MAX_LIMB) {
        return Err(TinyFError::OutsideInstanceClass);
    }
    Ok(BookWalkOutput {
        levels,
        take_left: take,
        fill_sum: Qty(fill_sum),
        notional_sum,
    })
}

/// Pad with zero-qty asks at the last price so `len` is a power of two ≥ 8.
pub fn pad_walk(mut instance: BookWalkInstance) -> Result<BookWalkInstance, TinyFError> {
    if instance.rests.is_empty() {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let last_p = instance.rests.last().unwrap().1;
    let n = instance.rests.len().next_power_of_two().max(8);
    instance.rests.resize(n, (Qty(0), last_p));
    Ok(instance)
}

/// k unit asks at 80, 81, … and a take that fills `take` of them.
pub fn unit_asks(k: usize, take: u64) -> BookWalkInstance {
    let rests = (0..k).map(|i| (Qty(1), Price(80 + i as u64))).collect();
    BookWalkInstance {
        rests,
        take_qty: Qty(take),
        take_price: Price(200),
    }
}

impl BookWalkStatement {
    pub fn prove_native(instance: BookWalkInstance) -> Result<Self, TinyFError> {
        let output = book_walk(instance.clone())?;
        Ok(Self { instance, output })
    }

    pub fn check(&self) -> Result<(), TinyFError> {
        let expected = book_walk(self.instance.clone())?;
        if expected == self.output {
            Ok(())
        } else {
            Err(TinyFError::OutputMismatch)
        }
    }
}

impl CanonicalEncode for BookWalkInstance {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"BKWALK\0\0");
        buf.u32(self.rests.len() as u32);
        for (q, p) in &self.rests {
            q.encode(buf);
            p.encode(buf);
        }
        self.take_qty.encode(buf);
        self.take_price.encode(buf);
    }
}

impl CanonicalEncode for BookWalkOutput {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"BKWOUT\0\0");
        buf.u32(self.levels.len() as u32);
        for lvl in &self.levels {
            lvl.encode(buf);
        }
        self.take_left.encode(buf);
        self.fill_sum.encode(buf);
        buf.u128(self.notional_sum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine_v1, limit_v1};
    use protocol_types::{Input, Side};

    fn clob_fill_sum(k: usize, take: u64) -> u64 {
        let mut engine = btree_engine_v1();
        for i in 0..k {
            let r = engine.apply(Input::Place(limit_v1(
                i as u128 + 1,
                1,
                Side::Sell,
                1,
                80 + i as u64,
                i as u64 + 1,
            )));
            assert!(r.fills.is_empty());
        }
        let t = engine.apply(Input::Place(limit_v1(
            k as u128 + 1,
            2,
            Side::Buy,
            take,
            200,
            1,
        )));
        t.fills.iter().map(|f| f.qty.0).sum()
    }

    #[test]
    fn unit_asks_8_matches_clob() {
        let s = BookWalkStatement::prove_native(unit_asks(8, 5)).unwrap();
        assert_eq!(s.output.fill_sum, Qty(5));
        assert_eq!(s.output.take_left, Qty(0));
        assert_eq!(s.output.levels[0].fill_qty, Qty(1));
        assert_eq!(s.output.levels[4].fill_qty, Qty(1));
        assert_eq!(s.output.levels[5].fill_qty, Qty(0));
        assert_eq!(s.output.fill_sum.0, clob_fill_sum(8, 5));
    }

    #[test]
    fn pad_to_eight() {
        let padded = pad_walk(unit_asks(5, 3)).unwrap();
        assert_eq!(padded.rests.len(), 8);
        let s = BookWalkStatement::prove_native(padded).unwrap();
        assert_eq!(s.output.fill_sum, Qty(3));
        assert_eq!(s.output.levels[5].fill_qty, Qty(0));
    }
}
