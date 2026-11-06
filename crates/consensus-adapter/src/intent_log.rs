//! Replicated intent set → sealed `I` (ADR 0016).
//!
//! Offer is set membership. A sealed id is spent (late gossip of the same
//! intent does not enter a later height). Seal orders by
//! `(owner, nonce, kind, id(intent))`. Not wall-clock FIFO. Not a gossip
//! mempool. Not FOCIL.

use std::collections::{BTreeMap, BTreeSet};

use commitments::Digest;
use protocol_types::{CanonicalEncode, EncodeBuf, Height, Input, OwnerId};

pub const INTENT_ID_DOMAIN: &[u8] = b"plx/intent/id/v1";
pub const INTENT_SET_DOMAIN: &[u8] = b"plx/intent/set/v1";

/// BLAKE3 of one canonical [`Input`].
pub fn intent_id(input: &Input) -> Digest {
    let mut buf = EncodeBuf::new();
    input.encode(&mut buf);
    Digest::from_bytes(buf.as_slice(), INTENT_ID_DOMAIN)
}

fn kind_rank(input: &Input) -> u8 {
    match input {
        Input::Place(_) => 0,
        Input::Cancel { .. } => 1,
        Input::AdvanceHeight { .. } => 2,
    }
}

fn owner_nonce(input: &Input) -> (OwnerId, u64) {
    match input {
        Input::Place(o) => (o.owner, o.nonce),
        Input::Cancel { owner, nonce, .. } => (*owner, *nonce),
        Input::AdvanceHeight { to } => (OwnerId::ZERO, to.0),
    }
}

fn sort_key(input: &Input) -> (OwnerId, u64, u8, Digest) {
    let (owner, nonce) = owner_nonce(input);
    (owner, nonce, kind_rank(input), intent_id(input))
}

/// Pending set plus sealed tapes per height.
///
/// Each pending intent carries a **target height**, fixed by the node that
/// first accepted it and carried with it in gossip (ADR 0027). Sealing height
/// `h` takes exactly the intents targeted `≤ h`, so a wave offered for the
/// next height can never be swept into the current one by a slower node.
///
/// `view == false` is withhold / missing fragments (`InsufficientView`).
#[derive(Clone, Debug)]
pub struct IntentLog {
    view: bool,
    /// target height → (intent id → input)
    pending: BTreeMap<u64, BTreeMap<Digest, Input>>,
    /// intent id → target height (dedupe across buckets).
    targets: BTreeMap<Digest, u64>,
    consumed: BTreeSet<Digest>,
    sealed: BTreeMap<u64, Vec<Input>>,
    /// Highest sealed height (0 = none).
    sealed_through: u64,
    /// Intents that arrived targeting an already-sealed height.
    late: u64,
}

impl IntentLog {
    pub fn hidden() -> Self {
        Self {
            view: false,
            ..Self::open()
        }
    }

    pub fn open() -> Self {
        Self {
            view: true,
            pending: BTreeMap::new(),
            targets: BTreeMap::new(),
            consumed: BTreeSet::new(),
            sealed: BTreeMap::new(),
            sealed_through: 0,
            late: 0,
        }
    }

    /// Open log already offered `batch`, or hidden if `None`.
    pub fn from_batch(batch: Option<Vec<Input>>) -> Self {
        match batch {
            None => Self::hidden(),
            Some(inputs) => {
                let mut log = Self::open();
                for input in inputs {
                    log.offer(input);
                }
                log
            }
        }
    }

    pub fn has_view(&self) -> bool {
        self.view
    }

    /// The next height a seal will take.
    pub fn next_open(&self) -> u64 {
        self.sealed_through + 1
    }

    /// Offer for the next open height.
    pub fn offer(&mut self, input: Input) -> bool {
        let h = self.next_open();
        self.offer_at(input, h)
    }

    /// Offer with a target height (from gossip, or chosen by the accepting
    /// node). The first target seen for an intent wins. A target at or below
    /// an already-sealed height moves to the next open one and counts as
    /// [`Self::late`]. Returns whether the intent is newly pending (false for
    /// a duplicate, an already-sealed intent, or no view).
    pub fn offer_at(&mut self, input: Input, height: u64) -> bool {
        if !self.view {
            return false;
        }
        let id = intent_id(&input);
        if self.consumed.contains(&id) || self.targets.contains_key(&id) {
            return false;
        }
        let h = if height <= self.sealed_through {
            self.late += 1;
            self.next_open()
        } else {
            height
        };
        self.targets.insert(id, h);
        self.pending.entry(h).or_default().insert(id, input);
        true
    }

    /// Every pending intent with its target height (for re-fan).
    pub fn pending(&self) -> Vec<(u64, Input)> {
        self.pending
            .iter()
            .flat_map(|(h, b)| b.values().map(move |i| (*h, i.clone())))
            .collect()
    }

    fn next_ids(&self) -> impl Iterator<Item = &Digest> {
        self.pending
            .range(..=self.next_open())
            .flat_map(|(_, b)| b.keys())
    }

    /// Intents the next seal will take (targets `≤` [`Self::next_open`]).
    pub fn pending_len(&self) -> usize {
        self.next_ids().count()
    }

    /// Membership id of what the next seal will take. Same set → same id
    /// (ADR 0021). Waves targeted at later heights do not change it, so an
    /// ACK quorum on it is stable (ADR 0027).
    pub fn pending_set_id(&self) -> Digest {
        let mut ids: Vec<&Digest> = self.next_ids().collect();
        ids.sort();
        let mut buf = Vec::with_capacity(ids.len() * 32);
        for id in ids {
            buf.extend_from_slice(&id.0);
        }
        Digest::from_bytes(&buf, INTENT_SET_DOMAIN)
    }

    /// Intents that arrived after their target height was sealed here.
    pub fn late(&self) -> u64 {
        self.late
    }

    /// Sealed `I` for `height`: the intents targeted `≤ height` (ADR 0016 /
    /// 0017 / 0027). Intents for later heights stay pending. `None` if no view.
    ///
    /// From height 2 on, `I` starts with the protocol's `AdvanceHeight { to:
    /// height }`, so engine height tracks consensus height and orders expire
    /// under consensus. It is part of `I`, so `input_commitment` and `π` cover
    /// it. Height 1 has none: the engine's genesis height is 1.
    pub fn tape(&mut self, height: u64) -> Option<&[Input]> {
        if !self.view {
            return None;
        }
        if !self.sealed.contains_key(&height) {
            let later = self.pending.split_off(&(height + 1));
            let taken = std::mem::replace(&mut self.pending, later);
            // Hash each intent once. Comparing `intent_id` inside the
            // comparator was n log n BLAKE3 and moved isolate ~0.18 → ~0.25 s.
            let mut keyed: Vec<_> = taken
                .into_values()
                .flat_map(|b| b.into_values())
                .map(|input| {
                    let key = sort_key(&input);
                    (key, input)
                })
                .collect();
            keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            let mut v = Vec::with_capacity(keyed.len() + 1);
            if height > 1 {
                v.push(Input::AdvanceHeight { to: Height(height) });
            }
            for (key, input) in keyed {
                self.targets.remove(&key.3);
                self.consumed.insert(key.3);
                v.push(input);
            }
            self.sealed.insert(height, v);
            self.sealed_through = self.sealed_through.max(height);
        }
        self.sealed.get(&height).map(|t| t.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{limit, oid, owner};
    use protocol_types::Side;

    fn place(id: u128, owner_n: u8, nonce: u64) -> Input {
        Input::Place(limit(id, owner_n, Side::Buy, 1, 10, nonce))
    }

    /// A sealed tape without the protocol's leading `AdvanceHeight`.
    fn client(tape: &[Input]) -> &[Input] {
        match tape.first() {
            Some(Input::AdvanceHeight { .. }) => &tape[1..],
            _ => tape,
        }
    }

    /// ADR 0027: the observed Q-CONS-11 race. Node A seals height 2, then a
    /// wave tagged for height 3 reaches both A and a slower node B before B
    /// seals 2. Both must seal the same `I(2)`, and the wave lands in `I(3)`.
    #[test]
    fn later_wave_cannot_enter_a_slower_nodes_current_height() {
        let w0: Vec<Input> = (1..=4).map(|n| place(n, 1, n as u64)).collect();
        let w1: Vec<Input> = (5..=8).map(|n| place(n, 2, n as u64)).collect();
        let (mut a, mut b) = (IntentLog::open(), IntentLog::open());
        for log in [&mut a, &mut b] {
            log.tape(1);
            for i in &w0 {
                log.offer_at(i.clone(), 2);
            }
        }
        let a2 = a.tape(2).unwrap().to_vec();
        // The wave is offered after A sealed 2, so it is tagged 3.
        for log in [&mut a, &mut b] {
            for i in &w1 {
                log.offer_at(i.clone(), 3);
            }
        }
        let b2 = b.tape(2).unwrap().to_vec();
        assert_eq!(a2, b2, "same I(2)");
        assert_eq!(client(&a2).len(), 4);
        assert_eq!(a.tape(3).unwrap(), b.tape(3).unwrap());
        assert_eq!(client(a.tape(3).unwrap()).len(), 4);
        assert_eq!((a.late(), b.late()), (0, 0));
    }

    #[test]
    fn set_id_ignores_later_heights() {
        let mut log = IntentLog::open();
        log.offer_at(place(1, 1, 1), 1);
        let before = log.pending_set_id();
        log.offer_at(place(2, 2, 1), 2);
        assert_eq!(log.pending_set_id(), before);
        assert_eq!(log.pending_len(), 1);
        assert_eq!(log.pending().len(), 2);
    }

    #[test]
    fn late_intent_moves_forward_and_first_target_wins() {
        let mut log = IntentLog::open();
        log.tape(1);
        log.offer_at(place(1, 1, 1), 1);
        assert_eq!(log.late(), 1);
        assert_eq!(log.pending(), vec![(2, place(1, 1, 1))]);
        log.offer_at(place(1, 1, 1), 5);
        assert_eq!(log.pending(), vec![(2, place(1, 1, 1))], "first target wins");
        assert_eq!(client(log.tape(2).unwrap()).len(), 1);
        log.offer_at(place(1, 1, 1), 3);
        assert!(log.pending().is_empty(), "consumed intents are not re-offered");
    }

    #[test]
    fn hidden_has_no_tape() {
        let mut log = IntentLog::hidden();
        log.offer(place(1, 1, 1));
        assert!(log.tape(1).is_none());
    }

    #[test]
    fn offer_order_does_not_change_set_id() {
        let a = place(1, 2, 1);
        let b = place(2, 1, 1);
        let mut x = IntentLog::open();
        x.offer(a.clone());
        x.offer(b.clone());
        let mut y = IntentLog::open();
        y.offer(b);
        y.offer(a);
        assert_eq!(x.pending_set_id(), y.pending_set_id());
        y.offer(place(3, 3, 1));
        assert_ne!(x.pending_set_id(), y.pending_set_id());
    }

    #[test]
    fn offer_order_does_not_change_sealed_i() {
        let a = place(1, 2, 1);
        let b = place(2, 1, 1);
        let mut x = IntentLog::open();
        x.offer(a.clone());
        x.offer(b.clone());
        let mut y = IntentLog::open();
        y.offer(b);
        y.offer(a);
        assert_eq!(x.tape(1), y.tape(1));
        let t = x.tape(1).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0], place(2, 1, 1));
        assert_eq!(t[1], place(1, 2, 1));
    }

    #[test]
    fn same_owner_keeps_nonce_order() {
        let mut log = IntentLog::open();
        log.offer(place(2, 1, 2));
        log.offer(place(1, 1, 1));
        let t = log.tape(1).unwrap();
        assert_eq!(t[0], place(1, 1, 1));
        assert_eq!(t[1], place(2, 1, 2));
    }

    #[test]
    fn heights_after_the_first_start_with_the_protocol_advance() {
        let mut log = IntentLog::open();
        log.offer(place(1, 1, 1));
        assert_eq!(log.tape(1).unwrap(), &[place(1, 1, 1)]);
        log.offer(place(2, 1, 2));
        assert_eq!(
            log.tape(2).unwrap(),
            &[Input::AdvanceHeight { to: Height(2) }, place(2, 1, 2)]
        );
        assert_eq!(log.tape(3).unwrap(), &[Input::AdvanceHeight { to: Height(3) }]);
    }

    #[test]
    fn offer_reports_only_newly_pending() {
        let mut log = IntentLog::open();
        assert!(log.offer(place(1, 1, 1)));
        assert!(!log.offer(place(1, 1, 1)), "duplicate");
        log.tape(1);
        assert!(!log.offer(place(1, 1, 1)), "already sealed");
        assert!(!IntentLog::hidden().offer(place(2, 1, 1)), "no view");
    }

    #[test]
    fn duplicate_offer_collapses() {
        let mut log = IntentLog::open();
        let p = place(1, 1, 1);
        log.offer(p.clone());
        log.offer(p);
        assert_eq!(log.tape(1).unwrap().len(), 1);
    }

    #[test]
    fn later_height_without_offers_is_empty() {
        let mut log = IntentLog::from_batch(Some(vec![place(1, 1, 1)]));
        assert_eq!(log.tape(1).unwrap().len(), 1);
        assert_eq!(client(log.tape(2).unwrap()).len(), 0);
    }

    #[test]
    fn pending_len_tracks_offers() {
        let mut log = IntentLog::open();
        assert_eq!(log.pending_len(), 0);
        log.offer(place(1, 1, 1));
        log.offer(place(2, 1, 2));
        assert_eq!(log.pending_len(), 2);
        let _ = log.tape(1);
        assert_eq!(log.pending_len(), 0);
    }

    #[test]
    fn offer_after_seal_is_next_height() {
        let mut log = IntentLog::open();
        log.offer(place(1, 1, 1));
        assert_eq!(log.tape(1).unwrap().len(), 1);
        log.offer(place(2, 1, 2));
        assert_eq!(client(log.tape(2).unwrap()), &[place(2, 1, 2)]);
    }

    #[test]
    fn resealed_intent_does_not_enter_next_height() {
        let mut log = IntentLog::open();
        let p = place(1, 1, 1);
        log.offer(p.clone());
        assert_eq!(log.tape(1).unwrap().len(), 1);
        log.offer(p);
        assert_eq!(log.pending_len(), 0);
        assert_eq!(client(log.tape(2).unwrap()).len(), 0);
    }

    #[test]
    fn cancel_sorts_after_place_same_owner_nonce() {
        let mut log = IntentLog::open();
        let c = Input::Cancel {
            order_id: oid(1),
            owner: owner(1),
            nonce: 1,
        };
        log.offer(c.clone());
        log.offer(place(1, 1, 1));
        let t = log.tape(1).unwrap();
        assert_eq!(t[0], place(1, 1, 1));
        assert_eq!(t[1], c);
    }
}
