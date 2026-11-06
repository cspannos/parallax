//! Mixed `I`: rest / take / cancel on a tiny slot book. Still 15-bit.
//!
//! This is the loaded-tape *shape* (½ rest, ¼ take, ¼ cancel), not an 8k book
//! and not `C'`. Takes are unit qty and hit the best rest only.

use protocol_types::{CanonicalEncode, EncodeBuf, Price, Qty};

use crate::match_step::{match_step, MatchStepInstance};
use crate::{TinyFError, MAX_LIMB, MAX_MIX_NOTIONAL};

pub const MIX_SLOTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MixKind {
    Rest = 0,
    Take = 1,
    Cancel = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixEvent {
    pub kind: MixKind,
    pub qty: Qty,
    pub price: Price,
    /// Cancel target. Rest/take ignore this (native finds empty/best).
    pub slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedInstance {
    pub slots: Vec<(Qty, Price)>,
    pub events: Vec<MixEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixedEventOut {
    pub kind: MixKind,
    pub fill_qty: Qty,
    pub remainder: Qty,
    pub notional: u128,
    pub slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedOutput {
    pub events: Vec<MixedEventOut>,
    pub slots: Vec<(Qty, Price)>,
    pub fill_sum: Qty,
    pub notional_sum: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedStatement {
    pub instance: MixedInstance,
    pub output: MixedOutput,
}

fn occupied(q: Qty) -> bool {
    q.0 > 0
}

fn first_empty(slots: &[(Qty, Price)]) -> Option<usize> {
    slots.iter().position(|(q, _)| !occupied(*q))
}

fn best_idx(slots: &[(Qty, Price)]) -> Option<usize> {
    slots
        .iter()
        .enumerate()
        .filter(|(_, (q, _))| occupied(*q))
        .min_by_key(|(i, (_, p))| (p.0, *i))
        .map(|(i, _)| i)
}

fn unique_occupied_prices(slots: &[(Qty, Price)]) -> bool {
    let mut ps: Vec<u64> = slots
        .iter()
        .filter(|(q, _)| occupied(*q))
        .map(|(_, p)| p.0)
        .collect();
    ps.sort_unstable();
    ps.windows(2).all(|w| w[0] != w[1])
}

pub fn mixed_f(instance: MixedInstance) -> Result<MixedOutput, TinyFError> {
    if instance.slots.len() != MIX_SLOTS
        || instance.events.is_empty()
        || !instance.events.len().is_power_of_two()
        || instance.events.len() < 8
    {
        return Err(TinyFError::OutsideInstanceClass);
    }
    for (q, p) in &instance.slots {
        if q.0 > MAX_LIMB || p.0 > MAX_LIMB {
            return Err(TinyFError::OutsideInstanceClass);
        }
    }
    if !unique_occupied_prices(&instance.slots) {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let mut slots = instance.slots.clone();
    let mut outs = Vec::with_capacity(instance.events.len());
    let mut fill_sum = 0u64;
    let mut notional_sum = 0u128;
    for ev in &instance.events {
        if ev.qty.0 > MAX_LIMB || ev.price.0 > MAX_LIMB || ev.slot >= MIX_SLOTS as u64 {
            return Err(TinyFError::OutsideInstanceClass);
        }
        let out = match ev.kind {
            MixKind::Rest => {
                if ev.qty.0 == 0 {
                    return Err(TinyFError::OutsideInstanceClass);
                }
                let i = first_empty(&slots).ok_or(TinyFError::OutsideInstanceClass)?;
                if slots.iter().any(|(q, p)| occupied(*q) && p.0 == ev.price.0) {
                    return Err(TinyFError::OutsideInstanceClass);
                }
                slots[i] = (ev.qty, ev.price);
                MixedEventOut {
                    kind: MixKind::Rest,
                    fill_qty: Qty(0),
                    remainder: ev.qty,
                    notional: 0,
                    slot: i as u64,
                }
            }
            MixKind::Take => {
                let Some(i) = best_idx(&slots) else {
                    return Err(TinyFError::OutsideInstanceClass);
                };
                let step = match_step(MatchStepInstance {
                    rest_qty: slots[i].0,
                    rest_price: slots[i].1,
                    take_qty: ev.qty,
                    take_price: ev.price,
                })?;
                slots[i].0 = step.remainder;
                MixedEventOut {
                    kind: MixKind::Take,
                    fill_qty: step.fill_qty,
                    remainder: step.remainder,
                    notional: step.notional,
                    slot: i as u64,
                }
            }
            MixKind::Cancel => {
                let i = ev.slot as usize;
                if !occupied(slots[i].0) {
                    return Err(TinyFError::OutsideInstanceClass);
                }
                let rem = slots[i].0;
                slots[i] = (Qty(0), slots[i].1);
                MixedEventOut {
                    kind: MixKind::Cancel,
                    fill_qty: Qty(0),
                    remainder: rem,
                    notional: 0,
                    slot: ev.slot,
                }
            }
        };
        fill_sum += out.fill_qty.0;
        notional_sum += out.notional;
        outs.push(out);
        if !unique_occupied_prices(&slots) {
            return Err(TinyFError::OutsideInstanceClass);
        }
    }
    if fill_sum > MAX_LIMB || notional_sum > MAX_MIX_NOTIONAL {
        return Err(TinyFError::OutsideInstanceClass);
    }
    Ok(MixedOutput {
        events: outs,
        slots,
        fill_sum: Qty(fill_sum),
        notional_sum,
    })
}

/// Empty 8-slot book. `k` events, `k` a power of two ≥ 8: rest, rest, take, cancel.
pub fn unit_mixed(k: usize) -> MixedInstance {
    let slots = vec![(Qty(0), Price(0)); MIX_SLOTS];
    let mut events = Vec::with_capacity(k);
    for cycle in 0..k / 4 {
        let p0 = 80 + 2 * cycle as u64;
        events.push(MixEvent {
            kind: MixKind::Rest,
            qty: Qty(1),
            price: Price(p0),
            slot: 0,
        });
        events.push(MixEvent {
            kind: MixKind::Rest,
            qty: Qty(1),
            price: Price(p0 + 1),
            slot: 0,
        });
        events.push(MixEvent {
            kind: MixKind::Take,
            qty: Qty(1),
            // Above every rest in the k≤8192 class (rests are 80, 81, …).
            price: Price(20_000),
            slot: 0,
        });
        events.push(MixEvent {
            kind: MixKind::Cancel,
            qty: Qty(0),
            price: Price(0),
            slot: 1,
        });
    }
    MixedInstance { slots, events }
}

impl MixedStatement {
    pub fn prove_native(instance: MixedInstance) -> Result<Self, TinyFError> {
        let output = mixed_f(instance.clone())?;
        Ok(Self { instance, output })
    }

    pub fn check(&self) -> Result<(), TinyFError> {
        let expected = mixed_f(self.instance.clone())?;
        if expected == self.output {
            Ok(())
        } else {
            Err(TinyFError::OutputMismatch)
        }
    }
}

impl CanonicalEncode for MixEvent {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"MIXEV\0\0\0");
        buf.u8(self.kind as u8);
        self.qty.encode(buf);
        self.price.encode(buf);
        buf.u64(self.slot);
    }
}

impl CanonicalEncode for MixedInstance {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"MIXINST\0");
        buf.u32(self.slots.len() as u32);
        for (q, p) in &self.slots {
            q.encode(buf);
            p.encode(buf);
        }
        buf.u32(self.events.len() as u32);
        for ev in &self.events {
            ev.encode(buf);
        }
    }
}

impl CanonicalEncode for MixedEventOut {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"MIXOUT\0\0");
        buf.u8(self.kind as u8);
        self.fill_qty.encode(buf);
        self.remainder.encode(buf);
        buf.u128(self.notional);
        buf.u64(self.slot);
    }
}

impl CanonicalEncode for MixedOutput {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"MIXRES\0\0");
        buf.u32(self.events.len() as u32);
        for ev in &self.events {
            ev.encode(buf);
        }
        buf.u32(self.slots.len() as u32);
        for (q, p) in &self.slots {
            q.encode(buf);
            p.encode(buf);
        }
        self.fill_sum.encode(buf);
        buf.u128(self.notional_sum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine_v1, limit_v1, owner};
    use clob::Book;
    use protocol_types::{Input, InstrumentId, OrderId, Side};

    fn clob_fill_sum(k: usize) -> u64 {
        let inst = unit_mixed(k);
        let mut engine = btree_engine_v1();
        let mut ids = [None; MIX_SLOTS];
        let mut next_id = 1u128;
        let mut fills = 0u64;
        for ev in &inst.events {
            match ev.kind {
                MixKind::Rest => {
                    let i = ids.iter().position(|id| id.is_none()).expect("empty");
                    let id = next_id;
                    next_id += 1;
                    let r = engine.apply(Input::Place(limit_v1(
                        id,
                        1,
                        Side::Sell,
                        ev.qty.0,
                        ev.price.0,
                        id as u64,
                    )));
                    assert!(r.fills.is_empty());
                    ids[i] = Some(id);
                }
                MixKind::Take => {
                    let id = next_id;
                    next_id += 1;
                    let r = engine.apply(Input::Place(limit_v1(
                        id,
                        2,
                        Side::Buy,
                        ev.qty.0,
                        ev.price.0,
                        id as u64,
                    )));
                    fills += r.fills.iter().map(|f| f.qty.0).sum::<u64>();
                    for slot in ids.iter_mut() {
                        if let Some(oid) = *slot {
                            let live = engine
                                .book(InstrumentId(1))
                                .and_then(|b| b.get(OrderId::from_u128(oid)))
                                .is_some();
                            if !live {
                                *slot = None;
                            }
                        }
                    }
                }
                MixKind::Cancel => {
                    let id = ids[ev.slot as usize].take().expect("live cancel");
                    engine.apply(Input::Cancel {
                        order_id: OrderId::from_u128(id),
                        owner: owner(1),
                        nonce: next_id as u64,
                    });
                    next_id += 1;
                }
            }
        }
        fills
    }

    #[test]
    fn unit_mixed_8_matches_clob() {
        let s = MixedStatement::prove_native(unit_mixed(8)).unwrap();
        assert_eq!(s.output.fill_sum, Qty(2));
        assert_eq!(s.output.notional_sum, 80 + 82);
        assert_eq!(s.instance.events.len(), 8);
        assert_eq!(s.output.events[0].kind, MixKind::Rest);
        assert_eq!(s.output.events[2].kind, MixKind::Take);
        assert_eq!(s.output.events[2].fill_qty, Qty(1));
        assert_eq!(s.output.events[3].kind, MixKind::Cancel);
        assert_eq!(s.output.fill_sum.0, clob_fill_sum(8));
        assert!(s.output.slots.iter().all(|(q, _)| q.0 == 0));
    }

    #[test]
    fn unit_mixed_32_matches_clob() {
        let s = MixedStatement::prove_native(unit_mixed(32)).unwrap();
        assert_eq!(s.output.fill_sum, Qty(8));
        assert_eq!(s.output.fill_sum.0, clob_fill_sum(32));
    }

    #[test]
    fn unit_mixed_128_fills_each_cycle() {
        let s = MixedStatement::prove_native(unit_mixed(128)).unwrap();
        assert_eq!(s.output.fill_sum, Qty(32));
        assert_eq!(s.output.events.len(), 128);
    }

    #[test]
    fn unit_mixed_8192_notional_fits_24_bits() {
        let s = MixedStatement::prove_native(unit_mixed(8192)).unwrap();
        assert_eq!(s.output.fill_sum, Qty(2048));
        assert!(s.output.notional_sum <= crate::MAX_MIX_NOTIONAL);
        assert!(s.output.notional_sum > u128::from(MAX_LIMB));
    }

    #[test]
    fn take_requires_a_rest() {
        let mut empty = unit_mixed(8);
        empty.events[0] = MixEvent {
            kind: MixKind::Take,
            qty: Qty(1),
            price: Price(200),
            slot: 0,
        };
        assert_eq!(mixed_f(empty), Err(TinyFError::OutsideInstanceClass));
    }
}
