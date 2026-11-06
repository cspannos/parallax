//! Two sell rests + one buy take. Still 15-bit. Still not `C'`, not height `π`.
//!
//! Instance class: `rest0.price <= rest1.price` so rest0 is best (or FIFO-first
//! at a tie). The take walks rest0, then rest1, at each maker price.

use protocol_types::{CanonicalEncode, EncodeBuf, Price, Qty};

use crate::match_step::{match_step, MatchStepInstance};
use crate::{TinyFError, MAX_LIMB};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookStepInstance {
    pub rest0_qty: Qty,
    pub rest0_price: Price,
    pub rest1_qty: Qty,
    pub rest1_price: Price,
    pub take_qty: Qty,
    pub take_price: Price,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookLevel {
    pub crosses: bool,
    pub fill_qty: Qty,
    pub remainder: Qty,
    pub notional: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookStepOutput {
    pub level0: BookLevel,
    pub level1: BookLevel,
    pub take_left: Qty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookStepStatement {
    pub instance: BookStepInstance,
    pub output: BookStepOutput,
}

/// Native spec: two asks, cheaper first; buy take walks both.
pub fn book_step(instance: BookStepInstance) -> Result<BookStepOutput, TinyFError> {
    if instance.rest0_qty.0 > MAX_LIMB
        || instance.rest0_price.0 > MAX_LIMB
        || instance.rest1_qty.0 > MAX_LIMB
        || instance.rest1_price.0 > MAX_LIMB
        || instance.take_qty.0 > MAX_LIMB
        || instance.take_price.0 > MAX_LIMB
        || instance.rest0_price.0 > instance.rest1_price.0
    {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let l0 = match_step(MatchStepInstance {
        rest_qty: instance.rest0_qty,
        rest_price: instance.rest0_price,
        take_qty: instance.take_qty,
        take_price: instance.take_price,
    })?;
    let take_after = Qty(instance.take_qty.0 - l0.fill_qty.0);
    let l1 = match_step(MatchStepInstance {
        rest_qty: instance.rest1_qty,
        rest_price: instance.rest1_price,
        take_qty: take_after,
        take_price: instance.take_price,
    })?;
    Ok(BookStepOutput {
        level0: BookLevel {
            crosses: l0.crosses,
            fill_qty: l0.fill_qty,
            remainder: l0.remainder,
            notional: l0.notional,
        },
        level1: BookLevel {
            crosses: l1.crosses,
            fill_qty: l1.fill_qty,
            remainder: l1.remainder,
            notional: l1.notional,
        },
        take_left: Qty(take_after.0 - l1.fill_qty.0),
    })
}

impl BookStepStatement {
    pub fn prove_native(instance: BookStepInstance) -> Result<Self, TinyFError> {
        let output = book_step(instance)?;
        Ok(Self { instance, output })
    }

    pub fn check(&self) -> Result<(), TinyFError> {
        let expected = book_step(self.instance)?;
        if expected == self.output {
            Ok(())
        } else {
            Err(TinyFError::OutputMismatch)
        }
    }
}

impl CanonicalEncode for BookStepInstance {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"BKINST\0\0");
        self.rest0_qty.encode(buf);
        self.rest0_price.encode(buf);
        self.rest1_qty.encode(buf);
        self.rest1_price.encode(buf);
        self.take_qty.encode(buf);
        self.take_price.encode(buf);
    }
}

impl CanonicalEncode for BookLevel {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"BKLVL\0\0\0");
        buf.u8(u8::from(self.crosses));
        self.fill_qty.encode(buf);
        self.remainder.encode(buf);
        buf.u128(self.notional);
    }
}

impl CanonicalEncode for BookStepOutput {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"BKOUT\0\0\0");
        self.level0.encode(buf);
        self.level1.encode(buf);
        self.take_left.encode(buf);
    }
}

impl CanonicalEncode for BookStepStatement {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"BKSTMT\0\0");
        self.instance.encode(buf);
        self.output.encode(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine_v1, limit_v1};
    use clob::Book;
    use protocol_types::{notional, Input, InstrumentId, OrderId, Side};

    fn clob_book(r0q: u64, r0p: u64, r1q: u64, r1p: u64, tq: u64, tp: u64) -> BookStepOutput {
        let mut engine = btree_engine_v1();
        assert!(engine
            .apply(Input::Place(limit_v1(1, 1, Side::Sell, r0q, r0p, 1)))
            .fills
            .is_empty());
        assert!(engine
            .apply(Input::Place(limit_v1(2, 2, Side::Sell, r1q, r1p, 2)))
            .fills
            .is_empty());
        let take = engine.apply(Input::Place(limit_v1(3, 3, Side::Buy, tq, tp, 1)));
        let book = engine.book(InstrumentId(1)).expect("book");
        let rem = |id: u128| {
            book.get(OrderId::from_u128(id))
                .map(|o| o.remaining)
                .unwrap_or(Qty(0))
        };
        let mut fills = take.fills.iter();
        let mut level = |rest_p: u64, id: u128| match fills.next() {
            Some(f) => {
                assert_eq!(f.price, Price(rest_p));
                BookLevel {
                    crosses: true,
                    fill_qty: f.qty,
                    remainder: rem(id),
                    notional: notional(f.qty, f.price),
                }
            }
            None => BookLevel {
                crosses: tp >= rest_p,
                fill_qty: Qty(0),
                remainder: rem(id),
                notional: 0,
            },
        };
        let level0 = level(r0p, 1);
        let level1 = level(r1p, 2);
        BookStepOutput {
            take_left: Qty(tq - level0.fill_qty.0 - level1.fill_qty.0),
            level0,
            level1,
        }
    }

    fn stmt(r0q: u64, r0p: u64, r1q: u64, r1p: u64, tq: u64, tp: u64) -> BookStepStatement {
        BookStepStatement::prove_native(BookStepInstance {
            rest0_qty: Qty(r0q),
            rest0_price: Price(r0p),
            rest1_qty: Qty(r1q),
            rest1_price: Price(r1p),
            take_qty: Qty(tq),
            take_price: Price(tp),
        })
        .unwrap()
    }

    #[test]
    fn walks_two_prices() {
        let s = stmt(5, 80, 10, 90, 12, 100);
        assert_eq!(s.output.level0.fill_qty, Qty(5));
        assert_eq!(s.output.level0.remainder, Qty(0));
        assert_eq!(s.output.level0.notional, 400);
        assert_eq!(s.output.level1.fill_qty, Qty(7));
        assert_eq!(s.output.level1.remainder, Qty(3));
        assert_eq!(s.output.level1.notional, 630);
        assert_eq!(s.output.take_left, Qty(0));
        assert_eq!(s.output, clob_book(5, 80, 10, 90, 12, 100));
    }

    #[test]
    fn stops_after_first_level() {
        let s = stmt(5, 80, 10, 90, 3, 100);
        assert_eq!(s.output.level0.fill_qty, Qty(3));
        assert_eq!(s.output.level1.fill_qty, Qty(0));
        assert_eq!(s.output.level1.remainder, Qty(10));
        assert_eq!(s.output, clob_book(5, 80, 10, 90, 3, 100));
    }

    #[test]
    fn equal_price_is_fifo() {
        let s = stmt(5, 90, 10, 90, 7, 90);
        assert_eq!(s.output.level0.fill_qty, Qty(5));
        assert_eq!(s.output.level1.fill_qty, Qty(2));
        assert_eq!(s.output, clob_book(5, 90, 10, 90, 7, 90));
    }

    #[test]
    fn no_cross_leaves_both() {
        let s = stmt(5, 80, 10, 90, 20, 70);
        assert!(!s.output.level0.crosses);
        assert_eq!(s.output.level0.fill_qty, Qty(0));
        assert_eq!(s.output.level1.fill_qty, Qty(0));
        assert_eq!(s.output.take_left, Qty(20));
        assert_eq!(s.output, clob_book(5, 80, 10, 90, 20, 70));
    }

    #[test]
    fn rejects_worse_first() {
        let err = book_step(BookStepInstance {
            rest0_qty: Qty(1),
            rest0_price: Price(90),
            rest1_qty: Qty(1),
            rest1_price: Price(80),
            take_qty: Qty(1),
            take_price: Price(100),
        });
        assert_eq!(err, Err(TinyFError::OutsideInstanceClass));
    }
}
