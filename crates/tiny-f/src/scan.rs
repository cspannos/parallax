//! One mixed event on a packed prefix book. Slots are rows in the AIR.
//!
//! Occupied asks sit in a price-sorted prefix; empties are the suffix.
//! A take hits the head. A rest appends. A cancel compact-shifts. This is
//! an 8k *book*, not eight columns. Still not `C'`. Still 15-bit qty/price.

use protocol_types::{CanonicalEncode, EncodeBuf, Price, Qty};

use crate::match_step::{match_step, MatchStepInstance};
use crate::mixed::{MixEvent, MixKind};
use crate::{TinyFError, MAX_LIMB};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanInstance {
    pub slots: Vec<(Qty, Price)>,
    pub event: MixEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanOutput {
    pub fill_qty: Qty,
    pub remainder: Qty,
    pub notional: u128,
    pub slot: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanStatement {
    pub instance: ScanInstance,
    pub output: ScanOutput,
    pub slots_out: Vec<(Qty, Price)>,
}

fn occupied_len(slots: &[(Qty, Price)]) -> usize {
    slots.iter().take_while(|(q, _)| q.0 > 0).count()
}

fn packed_sorted(slots: &[(Qty, Price)]) -> bool {
    let mut seen_empty = false;
    let mut prev_p = 0u64;
    for (q, p) in slots {
        if q.0 > MAX_LIMB || p.0 > MAX_LIMB {
            return false;
        }
        if q.0 == 0 {
            seen_empty = true;
            continue;
        }
        if seen_empty || p.0 < prev_p {
            return false;
        }
        prev_p = p.0;
    }
    true
}

fn compact_from(slots: &mut [(Qty, Price)], i: usize) {
    let n = slots.len();
    for j in i..n - 1 {
        slots[j] = slots[j + 1];
    }
    slots[n - 1] = (Qty(0), Price(0));
}

pub fn scan_event(instance: ScanInstance) -> Result<(ScanOutput, Vec<(Qty, Price)>), TinyFError> {
    let n = instance.slots.len();
    if n < 8 || !n.is_power_of_two() || !packed_sorted(&instance.slots) {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let ev = instance.event;
    if ev.qty.0 > MAX_LIMB || ev.price.0 > MAX_LIMB || ev.slot >= n as u64 {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let mut slots = instance.slots;
    let occ = occupied_len(&slots);
    let out = match ev.kind {
        MixKind::Rest => {
            if ev.qty.0 == 0 || occ == n {
                return Err(TinyFError::OutsideInstanceClass);
            }
            if occ > 0 && ev.price.0 < slots[occ - 1].1 .0 {
                return Err(TinyFError::OutsideInstanceClass);
            }
            slots[occ] = (ev.qty, ev.price);
            ScanOutput {
                fill_qty: Qty(0),
                remainder: ev.qty,
                notional: 0,
                slot: occ as u64,
            }
        }
        MixKind::Take => {
            if occ == 0 {
                return Err(TinyFError::OutsideInstanceClass);
            }
            let step = match_step(MatchStepInstance {
                rest_qty: slots[0].0,
                rest_price: slots[0].1,
                take_qty: ev.qty,
                take_price: ev.price,
            })?;
            if step.remainder.0 == 0 {
                compact_from(&mut slots, 0);
            } else {
                slots[0].0 = step.remainder;
            }
            ScanOutput {
                fill_qty: step.fill_qty,
                remainder: step.remainder,
                notional: step.notional,
                slot: 0,
            }
        }
        MixKind::Cancel => {
            let i = ev.slot as usize;
            if i >= occ {
                return Err(TinyFError::OutsideInstanceClass);
            }
            let rem = slots[i].0;
            compact_from(&mut slots, i);
            ScanOutput {
                fill_qty: Qty(0),
                remainder: rem,
                notional: 0,
                slot: ev.slot,
            }
        }
    };
    if !packed_sorted(&slots) {
        return Err(TinyFError::OutsideInstanceClass);
    }
    Ok((out, slots))
}

/// `n` unit asks at 80, 81, … (packed prefix, no empties).
pub fn unit_scan_book(n: usize) -> Vec<(Qty, Price)> {
    (0..n).map(|i| (Qty(1), Price(80 + i as u64))).collect()
}

/// Eight events on a full `n`-ask book: cancel tail, rest, take, …
pub fn unit_scan_tape(n: usize) -> Vec<MixEvent> {
    let mut events = Vec::with_capacity(8);
    let mut occ = n as u64;
    let mut extra = 0u64;
    for _ in 0..2 {
        events.push(MixEvent {
            kind: MixKind::Cancel,
            qty: Qty(0),
            price: Price(0),
            slot: occ - 1,
        });
        occ -= 1;
        extra += 1;
        events.push(MixEvent {
            kind: MixKind::Rest,
            qty: Qty(1),
            price: Price(80 + n as u64 + extra - 1),
            slot: 0,
        });
        occ += 1;
        events.push(MixEvent {
            kind: MixKind::Take,
            qty: Qty(1),
            price: Price(20_000),
            slot: 0,
        });
        occ -= 1;
    }
    events.push(MixEvent {
        kind: MixKind::Cancel,
        qty: Qty(0),
        price: Price(0),
        slot: occ - 1,
    });
    extra += 1;
    events.push(MixEvent {
        kind: MixKind::Rest,
        qty: Qty(1),
        price: Price(80 + n as u64 + extra - 1),
        slot: 0,
    });
    events
}

pub fn apply_scan_tape(
    mut slots: Vec<(Qty, Price)>,
    events: &[MixEvent],
) -> Result<(Vec<ScanOutput>, Vec<(Qty, Price)>), TinyFError> {
    let mut outs = Vec::with_capacity(events.len());
    for &event in events {
        let (out, next) = scan_event(ScanInstance {
            slots,
            event,
        })?;
        outs.push(out);
        slots = next;
    }
    Ok((outs, slots))
}

impl ScanStatement {
    pub fn prove_native(instance: ScanInstance) -> Result<Self, TinyFError> {
        let (output, slots_out) = scan_event(instance.clone())?;
        Ok(Self {
            instance,
            output,
            slots_out,
        })
    }

    pub fn check(&self) -> Result<(), TinyFError> {
        let (expected, slots_out) = scan_event(self.instance.clone())?;
        if expected == self.output && slots_out == self.slots_out {
            Ok(())
        } else {
            Err(TinyFError::OutputMismatch)
        }
    }
}

impl CanonicalEncode for ScanInstance {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"SCANIN\0\0");
        buf.u32(self.slots.len() as u32);
        for (q, p) in &self.slots {
            q.encode(buf);
            p.encode(buf);
        }
        self.event.encode(buf);
    }
}

impl CanonicalEncode for ScanOutput {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"SCANOUT\0");
        self.fill_qty.encode(buf);
        self.remainder.encode(buf);
        buf.u128(self.notional);
        buf.u64(self.slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine_v1, limit_v1, owner};
    use clob::Book;
    use protocol_types::{Input, InstrumentId, OrderId, Side};

    fn clob_tape(n: usize) -> u64 {
        let mut engine = btree_engine_v1();
        let mut ids: Vec<u128> = Vec::with_capacity(n);
        for i in 0..n {
            let id = i as u128 + 1;
            assert!(engine
                .apply(Input::Place(limit_v1(id, 1, Side::Sell, 1, 80 + i as u64, id as u64)))
                .fills
                .is_empty());
            ids.push(id);
        }
        let mut next_id = n as u128 + 1;
        let mut fills = 0u64;
        for ev in unit_scan_tape(n) {
            match ev.kind {
                MixKind::Rest => {
                    let id = next_id;
                    next_id += 1;
                    assert!(engine
                        .apply(Input::Place(limit_v1(
                            id,
                            1,
                            Side::Sell,
                            ev.qty.0,
                            ev.price.0,
                            id as u64,
                        )))
                        .fills
                        .is_empty());
                    ids.push(id);
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
                    ids.retain(|&oid| {
                        engine
                            .book(InstrumentId(1))
                            .and_then(|b| b.get(OrderId::from_u128(oid)))
                            .is_some()
                    });
                }
                MixKind::Cancel => {
                    let idx = ev.slot as usize;
                    let id = ids.remove(idx);
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
    fn scan_tape_8_matches_clob() {
        let slots = unit_scan_book(8);
        let events = unit_scan_tape(8);
        let (outs, _) = apply_scan_tape(slots, &events).unwrap();
        let fill: u64 = outs.iter().map(|o| o.fill_qty.0).sum();
        assert_eq!(fill, 2);
        assert_eq!(fill, clob_tape(8));
        assert_eq!(events.len(), 8);
    }

    #[test]
    fn take_compacts_the_head() {
        let s = ScanStatement::prove_native(ScanInstance {
            slots: unit_scan_book(8),
            event: MixEvent {
                kind: MixKind::Take,
                qty: Qty(1),
                price: Price(20_000),
                slot: 0,
            },
        })
        .unwrap();
        assert_eq!(s.output.fill_qty, Qty(1));
        assert_eq!(s.slots_out[0].1, Price(81));
        assert_eq!(s.slots_out[7].0, Qty(0));
    }

    #[test]
    fn cancel_tail_then_rest() {
        let (out, slots) = scan_event(ScanInstance {
            slots: unit_scan_book(8),
            event: MixEvent {
                kind: MixKind::Cancel,
                qty: Qty(0),
                price: Price(0),
                slot: 7,
            },
        })
        .unwrap();
        assert_eq!(out.slot, 7);
        assert_eq!(slots[7].0, Qty(0));
        let (out, slots) = scan_event(ScanInstance {
            slots,
            event: MixEvent {
                kind: MixKind::Rest,
                qty: Qty(1),
                price: Price(90),
                slot: 0,
            },
        })
        .unwrap();
        assert_eq!(out.slot, 7);
        assert_eq!(slots[7], (Qty(1), Price(90)));
    }
}
