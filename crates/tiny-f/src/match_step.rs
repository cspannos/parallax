//! One rest + one incoming take. Still 15-bit, still not the book, not height `π`.
//!
//! Rest is a sell limit; take is a buy limit. Fill is at the maker price when
//! the take crosses (`take_price >= rest_price`). Otherwise fill is zero and
//! the rest stays.

use protocol_types::{notional, CanonicalEncode, EncodeBuf, Price, Qty};

use crate::{TinyFError, MAX_LIMB};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchStepInstance {
    pub rest_qty: Qty,
    pub rest_price: Price,
    pub take_qty: Qty,
    pub take_price: Price,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchStepOutput {
    pub crosses: bool,
    pub fill_qty: Qty,
    pub fill_price: Price,
    pub remainder: Qty,
    pub notional: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchStepStatement {
    pub instance: MatchStepInstance,
    pub output: MatchStepOutput,
}

/// Native spec: sell rest, buy take, fill at maker if `take_price >= rest_price`.
pub fn match_step(instance: MatchStepInstance) -> Result<MatchStepOutput, TinyFError> {
    if instance.rest_qty.0 > MAX_LIMB
        || instance.rest_price.0 > MAX_LIMB
        || instance.take_qty.0 > MAX_LIMB
        || instance.take_price.0 > MAX_LIMB
    {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let crosses = instance.take_price.0 >= instance.rest_price.0;
    let fill_qty = if crosses {
        instance.rest_qty.saturating_min(instance.take_qty)
    } else {
        Qty(0)
    };
    let fill_price = instance.rest_price;
    Ok(MatchStepOutput {
        crosses,
        fill_qty,
        fill_price,
        remainder: Qty(instance.rest_qty.0 - fill_qty.0),
        notional: notional(fill_qty, fill_price),
    })
}

impl MatchStepStatement {
    pub fn prove_native(instance: MatchStepInstance) -> Result<Self, TinyFError> {
        let output = match_step(instance)?;
        Ok(Self { instance, output })
    }

    pub fn check(&self) -> Result<(), TinyFError> {
        let expected = match_step(self.instance)?;
        if expected == self.output {
            Ok(())
        } else {
            Err(TinyFError::OutputMismatch)
        }
    }
}

impl CanonicalEncode for MatchStepInstance {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"MCHINST\0");
        self.rest_qty.encode(buf);
        self.rest_price.encode(buf);
        self.take_qty.encode(buf);
        self.take_price.encode(buf);
    }
}

impl CanonicalEncode for MatchStepOutput {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"MCHOUT\0\0");
        buf.u8(u8::from(self.crosses));
        self.fill_qty.encode(buf);
        self.fill_price.encode(buf);
        self.remainder.encode(buf);
        buf.u128(self.notional);
    }
}

impl CanonicalEncode for MatchStepStatement {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"MCHSTMT\0");
        self.instance.encode(buf);
        self.output.encode(buf);
    }
}

impl protocol_types::CanonicalDecode for MatchStepInstance {
    fn decode(
        buf: &mut protocol_types::DecodeBuf<'_>,
    ) -> Result<Self, protocol_types::DecodeError> {
        buf.expect_tag(*b"MCHINST\0")?;
        Ok(Self {
            rest_qty: <Qty as protocol_types::CanonicalDecode>::decode(buf)?,
            rest_price: <Price as protocol_types::CanonicalDecode>::decode(buf)?,
            take_qty: <Qty as protocol_types::CanonicalDecode>::decode(buf)?,
            take_price: <Price as protocol_types::CanonicalDecode>::decode(buf)?,
        })
    }
}

impl protocol_types::CanonicalDecode for MatchStepOutput {
    fn decode(
        buf: &mut protocol_types::DecodeBuf<'_>,
    ) -> Result<Self, protocol_types::DecodeError> {
        buf.expect_tag(*b"MCHOUT\0\0")?;
        let crosses = buf.u8()? != 0;
        Ok(Self {
            crosses,
            fill_qty: <Qty as protocol_types::CanonicalDecode>::decode(buf)?,
            fill_price: <Price as protocol_types::CanonicalDecode>::decode(buf)?,
            remainder: <Qty as protocol_types::CanonicalDecode>::decode(buf)?,
            notional: buf.u128()?,
        })
    }
}

impl protocol_types::CanonicalDecode for MatchStepStatement {
    fn decode(
        buf: &mut protocol_types::DecodeBuf<'_>,
    ) -> Result<Self, protocol_types::DecodeError> {
        buf.expect_tag(*b"MCHSTMT\0")?;
        Ok(Self {
            instance: MatchStepInstance::decode(buf)?,
            output: MatchStepOutput::decode(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine_v1, limit_v1};
    use clob::Book;
    use protocol_types::{Input, InstrumentId, Side};

    fn clob_step(rest_qty: u64, rest_px: u64, take_qty: u64, take_px: u64) -> MatchStepOutput {
        let mut engine = btree_engine_v1();
        let rest = engine.apply(Input::Place(limit_v1(1, 1, Side::Sell, rest_qty, rest_px, 1)));
        assert!(rest.fills.is_empty());
        let take = engine.apply(Input::Place(limit_v1(2, 2, Side::Buy, take_qty, take_px, 1)));
        let book = engine.book(InstrumentId(1)).expect("book");
        let remainder = book
            .get(protocol_types::OrderId::from_u128(1))
            .map(|o| o.remaining)
            .unwrap_or(Qty(0));
        if take.fills.is_empty() {
            MatchStepOutput {
                crosses: false,
                fill_qty: Qty(0),
                fill_price: Price(rest_px),
                remainder,
                notional: 0,
            }
        } else {
            assert_eq!(take.fills.len(), 1);
            let f = &take.fills[0];
            MatchStepOutput {
                crosses: true,
                fill_qty: f.qty,
                fill_price: f.price,
                remainder,
                notional: notional(f.qty, f.price),
            }
        }
    }

    #[test]
    fn partial_cross_matches_clob() {
        let stmt = MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(7),
            take_price: Price(100),
        })
        .unwrap();
        assert!(stmt.output.crosses);
        assert_eq!(stmt.output.fill_qty, Qty(7));
        assert_eq!(stmt.output.fill_price, Price(90));
        assert_eq!(stmt.output.remainder, Qty(3));
        assert_eq!(stmt.output.notional, 630);
        assert_eq!(stmt.output, clob_step(10, 90, 7, 100));
    }

    #[test]
    fn equal_price_crosses_at_maker() {
        let stmt = MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(10),
            take_price: Price(90),
        })
        .unwrap();
        assert!(stmt.output.crosses);
        assert_eq!(stmt.output.remainder, Qty(0));
        assert_eq!(stmt.output, clob_step(10, 90, 10, 90));
    }

    #[test]
    fn no_cross_leaves_the_rest() {
        let stmt = MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(7),
            take_price: Price(89),
        })
        .unwrap();
        assert!(!stmt.output.crosses);
        assert_eq!(stmt.output.fill_qty, Qty(0));
        assert_eq!(stmt.output.remainder, Qty(10));
        assert_eq!(stmt.output.notional, 0);
        assert_eq!(stmt.output, clob_step(10, 90, 7, 89));
    }

    #[test]
    fn rejects_outside_instance_class() {
        let err = match_step(MatchStepInstance {
            rest_qty: Qty(MAX_LIMB + 1),
            rest_price: Price(1),
            take_qty: Qty(1),
            take_price: Price(1),
        });
        assert_eq!(err, Err(TinyFError::OutsideInstanceClass));
    }

    #[test]
    fn statement_roundtrips() {
        use protocol_types::CanonicalDecode;
        let stmt = MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(10),
            take_price: Price(100),
        })
        .unwrap();
        let bytes = stmt.encode_vec();
        assert_eq!(MatchStepStatement::decode_slice(&bytes).unwrap(), stmt);
    }
}
