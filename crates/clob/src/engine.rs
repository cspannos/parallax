use std::collections::BTreeMap;

use commitments::{Digest, StateHasher, StateRoot, TreapHash};
use protocol_types::{
    notional, EncodeBuf, Fill, Height, Input, Instrument, InstrumentId, Order, OrderId, OwnerId,
    Price, Qty, SettlementDelta, Side, TimeSeq,
};

use crate::book::{Book, RestingOrder};
use crate::btree_book::BTreeBook;
use crate::incremental::IncrementalState;

#[derive(Clone, Debug)]
pub struct Genesis {
    pub height: Height,
    pub instruments: Vec<Instrument>,
}

impl Default for Genesis {
    fn default() -> Self {
        Self {
            height: Height(1),
            instruments: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    pub places: u64,
    pub cancels: u64,
    pub rejects: u64,
    pub fills: u64,
    pub height_advances: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    ZeroQuantity,
    ZeroPrice,
    ZeroNonce,
    UnknownInstrument,
    QuantityNotMultipleOfLot,
    PriceNotMultipleOfTick,
    Expired,
    DuplicateOrderId,
    NonceReplay,
    /// [`OrderIdRule::DerivedFromOwnerNonce`]: the id is not `derive_order_id(owner, nonce)`.
    OrderIdMismatch,
    UnknownOrder,
    OwnerMismatch,
    HeightNotMonotonic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Rejected(RejectReason),
    /// Limit placed; `remaining` is unfilled qty (zero = fully filled, nothing rests).
    Accepted {
        remaining: Qty,
    },
    Cancelled {
        cancelled: Qty,
    },
    HeightAdvanced {
        expired: Vec<OrderId>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub outcome: Outcome,
    pub fills: Vec<Fill>,
    pub settlement: Vec<SettlementDelta>,
    pub state_root: StateRoot,
}

/// How order ids are admitted (ADR 0026).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OrderIdRule {
    /// v1: client-chosen ids, globally unique via the seen-id set (grows forever).
    ClientChosen,
    /// Production: `order_id = derive_order_id(owner, nonce)`. Uniqueness follows
    /// from per-owner nonce monotonicity; the seen set stays empty.
    #[default]
    DerivedFromOwnerNonce,
}

#[derive(Clone, Debug)]
pub struct Engine<B: Book = BTreeBook> {
    height: Height,
    next_time: TimeSeq,
    instruments: BTreeMap<InstrumentId, Instrument>,
    books: BTreeMap<InstrumentId, B>,
    last_nonce: BTreeMap<OwnerId, u64>,
    /// Global uniqueness of order ids (including fully filled / cancelled).
    seen_ids: BTreeMap<OrderId, ()>,
    /// When false, receipts carry a zero digest. Matching is unchanged.
    /// Used to separate matcher latency from commitment work.
    pub commit_on_apply: bool,
    /// When true (default), maintain the treap on every mutation. Then
    /// [`Self::state_root`] is `C'` (ADR 0013). Matcher micros turn this off.
    pub incremental_on_apply: bool,
    inc: IncrementalState,
    treap_hash: TreapHash,
    id_rule: OrderIdRule,
    pub metrics: Metrics,
}

impl<B: Book> Engine<B> {
    pub fn new(genesis: Genesis) -> Self {
        let mut instruments = BTreeMap::new();
        let mut books = BTreeMap::new();
        for spec in genesis.instruments {
            books.insert(spec.id, B::default());
            instruments.insert(spec.id, spec);
        }
        let inc = IncrementalState::new(genesis.height, instruments.values().cloned());
        Self {
            height: genesis.height,
            next_time: TimeSeq(0),
            instruments,
            books,
            last_nonce: BTreeMap::new(),
            seen_ids: BTreeMap::new(),
            commit_on_apply: true,
            incremental_on_apply: true,
            inc,
            treap_hash: TreapHash::default(),
            id_rule: OrderIdRule::default(),
            metrics: Metrics::default(),
        }
    }

    pub fn height(&self) -> Height {
        self.height
    }

    pub fn book(&self, id: InstrumentId) -> Option<&B> {
        self.books.get(&id)
    }

    pub fn apply(&mut self, input: Input) -> Receipt {
        match input {
            Input::Place(order) => self.place(order),
            Input::Cancel {
                order_id,
                owner,
                nonce,
            } => self.cancel(order_id, owner, nonce),
            Input::AdvanceHeight { to } => self.advance_height(to),
        }
    }

    /// Applies the batch, then hashes the touched treap nodes once (lazy
    /// `C'`, ADR 0032) rather than once per input.
    pub fn apply_all(&mut self, inputs: impl IntoIterator<Item = Input>) -> Vec<Receipt> {
        let out = inputs.into_iter().map(|i| self.apply(i)).collect();
        self.flush_commitments();
        out
    }

    /// Hash pending lazy `C'` changes. Roots are correct without this; it
    /// only makes repeated root reads cheap.
    pub fn flush_commitments(&mut self) {
        self.inc.flush();
    }

    /// Consensus `C'` (ADR 0013): treap when [`Self::incremental_on_apply`],
    /// else the O(n) walk.
    pub fn state_root(&self) -> StateRoot {
        if self.incremental_on_apply {
            self.inc.root()
        } else {
            self.full_walk_root()
        }
    }

    /// O(n) Blake3 walk (`plx/clob/state/v1`). Not voted as `id(v)`.
    pub fn full_walk_root(&self) -> StateRoot {
        let mut h = StateHasher::new();
        h.tag(b"height");
        h.write_encoded(&self.height);
        h.tag(b"next_t");
        h.write_encoded(&self.next_time);
        h.tag(b"instrs");
        for spec in self.instruments.values() {
            h.write_encoded(spec);
        }
        h.tag(b"nonces");
        for (owner, nonce) in &self.last_nonce {
            h.write_encoded(owner);
            h.write_encoded(nonce);
        }
        h.tag(b"seenid");
        for id in self.seen_ids.keys() {
            h.write_encoded(id);
        }
        h.tag(b"books");
        for (id, book) in &self.books {
            h.write_encoded(id);
            book.visit_canonical(&mut |order| {
                let mut buf = EncodeBuf::new();
                order.encode_leaf(&mut buf);
                h.write(buf.as_slice());
            });
        }
        h.finalize()
    }

    /// Treap forest (`plx/clob/inc/v1`). Same as [`Self::state_root`] when tracking.
    pub fn incremental_root(&self) -> StateRoot {
        self.inc.root()
    }

    /// Preimage of [`Self::incremental_root`]. Not a `node_digest`.
    pub fn incremental_root_preimage(&self) -> Vec<u8> {
        self.inc.root_preimage()
    }

    /// `(nonces, seen, resting)` treap roots inside [`Self::incremental_root`].
    pub fn incremental_map_roots(&self) -> (StateRoot, StateRoot, StateRoot) {
        self.inc.map_roots()
    }

    /// `C'` hash mode ([`commitments::IncTape::hash`]).
    pub fn treap_hash(&self) -> TreapHash {
        self.treap_hash
    }

    pub fn order_id_rule(&self) -> OrderIdRule {
        self.id_rule
    }

    /// Set at genesis (before any Place). v1 fixtures use [`OrderIdRule::ClientChosen`].
    pub fn set_order_id_rule(&mut self, rule: OrderIdRule) {
        self.id_rule = rule;
    }

    /// Non-map INC fields for [`commitments::IncTape`].
    pub fn incremental_inc_header(&self) -> commitments::IncHeader {
        self.inc.inc_header()
    }

    /// `(height, next_time, instruments)` inside [`Self::incremental_root`].
    /// Not `C'`. Not the consensus height field of `HeightStatement` in general;
    /// on this 2-place fixture they are `Height(1)`, `TimeSeq(1)`, genesis instruments.
    pub fn incremental_header(&self) -> (Height, TimeSeq, StateRoot) {
        (
            self.inc.height(),
            self.inc.next_time(),
            self.inc.instruments_root(),
        )
    }

    pub fn incremental_resting_len(&self) -> usize {
        self.inc.resting_len()
    }

    /// `C'` hash mode. Production is [`TreapHash::Sha256`] (ADR 0024); `Blake3`
    /// is `C'` v1 (Plonky3 fixtures); the rest are isolate modes.
    pub fn set_treap_hash(&mut self, hash: TreapHash) {
        self.treap_hash = hash;
        self.inc = self.rebuild_incremental();
    }

    /// Rebuild maps from current fields and keep them updated on later applies.
    pub fn enable_incremental(&mut self) {
        self.inc = self.rebuild_incremental();
        self.incremental_on_apply = true;
    }

    /// Canonical snapshot of every field `F` reads ([`crate::snapshot`]).
    pub fn snapshot(&self) -> crate::snapshot::EngineSnapshot {
        let mut resting = Vec::new();
        for book in self.books.values() {
            book.visit_canonical(&mut |o| resting.push(o.clone()));
        }
        resting.sort_by_key(|o| o.time);
        crate::snapshot::EngineSnapshot {
            hash: self.treap_hash,
            id_rule: self.id_rule,
            height: self.height,
            next_time: self.next_time,
            instruments: self.instruments.values().cloned().collect(),
            nonces: self.last_nonce.iter().map(|(o, n)| (*o, *n)).collect(),
            seen: self.seen_ids.keys().copied().collect(),
            resting,
        }
    }

    /// Rebuild from a canonical snapshot; books in `time` (FIFO) order, `C'`
    /// rebuilt from the fields. Rejects any non-canonical snapshot.
    pub fn from_snapshot(
        snap: &crate::snapshot::EngineSnapshot,
    ) -> Result<Self, crate::snapshot::SnapshotError> {
        let by_id = snap.validated_id_order()?;
        let mut e = Self::new(Genesis {
            height: snap.height,
            instruments: snap.instruments.clone(),
        });
        e.treap_hash = snap.hash;
        e.id_rule = snap.id_rule;
        e.next_time = snap.next_time;
        e.last_nonce = snap.nonces.iter().copied().collect();
        e.seen_ids = snap.seen.iter().map(|id| (*id, ())).collect();
        if let [only] = snap.instruments.as_slice() {
            e.books.get_mut(&only.id).expect("book").reserve(snap.resting.len());
        }
        for o in &snap.resting {
            e.books
                .get_mut(&o.instrument)
                .expect("validated instrument")
                .insert(o.clone());
        }
        e.inc = IncrementalState::from_parts(
            snap.height,
            snap.instruments.iter().cloned(),
            snap.hash,
            snap.next_time,
            snap.nonces.iter().copied(),
            snap.seen.iter().copied(),
            by_id.iter().map(|&i| &snap.resting[i as usize]),
        );
        Ok(e)
    }

    fn rebuild_incremental(&self) -> IncrementalState {
        let mut inc = IncrementalState::with_hash(
            self.height,
            self.instruments.values().cloned(),
            self.treap_hash,
        );
        inc.set_next_time(self.next_time);
        for (owner, nonce) in &self.last_nonce {
            inc.upsert_nonce(*owner, *nonce);
        }
        for id in self.seen_ids.keys() {
            inc.note_seen(*id);
        }
        for book in self.books.values() {
            book.visit_canonical(&mut |order| inc.upsert_resting(order));
        }
        inc.flush();
        inc
    }

    /// Per-receipt root. Flushes first: with lazy `C'` (ADR 0032), reading a
    /// root over dirty nodes recomputes them without storing, so per-input
    /// reads would otherwise be quadratic in the batch.
    fn receipt_root(&mut self) -> StateRoot {
        if self.commit_on_apply {
            self.flush_commitments();
            self.state_root()
        } else {
            Digest([0; 32])
        }
    }

    fn reject(&mut self, reason: RejectReason) -> Receipt {
        self.metrics.rejects += 1;
        Receipt {
            outcome: Outcome::Rejected(reason),
            fills: Vec::new(),
            settlement: Vec::new(),
            state_root: self.receipt_root(),
        }
    }

    fn consume_nonce(&mut self, owner: OwnerId, nonce: u64) -> Result<(), RejectReason> {
        if nonce == 0 {
            return Err(RejectReason::ZeroNonce);
        }
        let last = self.last_nonce.get(&owner).copied().unwrap_or(0);
        if nonce <= last {
            return Err(RejectReason::NonceReplay);
        }
        self.last_nonce.insert(owner, nonce);
        if self.incremental_on_apply {
            self.inc.upsert_nonce(owner, nonce);
        }
        Ok(())
    }

    fn place(&mut self, order: Order) -> Receipt {
        if order.quantity.is_zero() {
            return self.reject(RejectReason::ZeroQuantity);
        }
        if order.limit_price.is_zero() {
            return self.reject(RejectReason::ZeroPrice);
        }
        if order.expiry < self.height {
            return self.reject(RejectReason::Expired);
        }
        match self.id_rule {
            OrderIdRule::ClientChosen => {
                if self.seen_ids.contains_key(&order.order_id) {
                    return self.reject(RejectReason::DuplicateOrderId);
                }
            }
            OrderIdRule::DerivedFromOwnerNonce => {
                if order.order_id != commitments::derive_order_id(&order.owner, order.nonce) {
                    return self.reject(RejectReason::OrderIdMismatch);
                }
            }
        }
        let spec = match self.instruments.get(&order.instrument) {
            Some(s) => s.clone(),
            None => return self.reject(RejectReason::UnknownInstrument),
        };
        if spec.lot_size.0 == 0 || order.quantity.0 % spec.lot_size.0 != 0 {
            return self.reject(RejectReason::QuantityNotMultipleOfLot);
        }
        if spec.tick_size.0 == 0 || order.limit_price.0 % spec.tick_size.0 != 0 {
            return self.reject(RejectReason::PriceNotMultipleOfTick);
        }
        if let Err(r) = self.consume_nonce(order.owner, order.nonce) {
            return self.reject(r);
        }
        // Derived ids: a replay is caught by the nonce above. This backstop only
        // fires on a 128-bit id collision, which would corrupt the id-keyed book.
        if self.id_rule == OrderIdRule::DerivedFromOwnerNonce
            && self.books.values().any(|b| b.contains(order.order_id))
        {
            return self.reject(RejectReason::DuplicateOrderId);
        }

        if self.id_rule == OrderIdRule::ClientChosen {
            self.seen_ids.insert(order.order_id, ());
            if self.incremental_on_apply {
                self.inc.note_seen(order.order_id);
            }
        }
        self.metrics.places += 1;

        let mut remaining = order.quantity;
        let mut fills = Vec::new();
        let mut settlement = Vec::new();

        loop {
            if remaining.is_zero() {
                break;
            }
            let maker_id = {
                let Some(book) = self.books.get(&order.instrument) else {
                    break;
                };
                match book.best_cross(order.side, order.limit_price, order.owner) {
                    Some(id) => id,
                    None => break,
                }
            };

            let (maker_owner, maker_price, maker_remaining, maker_expiry) = {
                let book = self.books.get(&order.instrument).expect("instrument book");
                let maker = book.get(maker_id).expect("maker id from best_cross");
                (maker.owner, maker.price, maker.remaining, maker.expiry)
            };

            if maker_expiry < self.height {
                self.books
                    .get_mut(&order.instrument)
                    .expect("book")
                    .remove(maker_id);
                if self.incremental_on_apply {
                    self.inc.remove_resting(maker_id);
                }
                continue;
            }

            let fill_qty = remaining.saturating_min(maker_remaining);
            let quote = notional(fill_qty, maker_price);
            let base = u128::from(fill_qty.0);

            self.books
                .get_mut(&order.instrument)
                .expect("book")
                .fill(maker_id, fill_qty)
                .expect("fill known maker");

            if self.incremental_on_apply {
                match self
                    .books
                    .get(&order.instrument)
                    .and_then(|b| b.get(maker_id))
                    .cloned()
                {
                    Some(resting) => self.inc.upsert_resting(&resting),
                    None => {
                        self.inc.remove_resting(maker_id);
                    }
                }
            }

            remaining = remaining
                .checked_sub(fill_qty)
                .expect("fill_qty <= remaining");

            fills.push(Fill {
                taker_order_id: order.order_id,
                maker_order_id: maker_id,
                taker: order.owner,
                maker: maker_owner,
                qty: fill_qty,
                price: maker_price,
            });
            self.metrics.fills += 1;

            let (taker_base_debit, taker_quote_debit) = match order.side {
                Side::Buy => (false, true),
                Side::Sell => (true, false),
            };
            settlement.push(if taker_base_debit {
                SettlementDelta::debit(order.owner, spec.base, base)
            } else {
                SettlementDelta::credit(order.owner, spec.base, base)
            });
            settlement.push(if taker_quote_debit {
                SettlementDelta::debit(order.owner, spec.quote, quote)
            } else {
                SettlementDelta::credit(order.owner, spec.quote, quote)
            });
            settlement.push(if taker_base_debit {
                SettlementDelta::credit(maker_owner, spec.base, base)
            } else {
                SettlementDelta::debit(maker_owner, spec.base, base)
            });
            settlement.push(if taker_quote_debit {
                SettlementDelta::credit(maker_owner, spec.quote, quote)
            } else {
                SettlementDelta::debit(maker_owner, spec.quote, quote)
            });
        }

        if !remaining.is_zero() {
            let time = self.next_time;
            self.next_time = TimeSeq(self.next_time.0.saturating_add(1));
            let resting = RestingOrder::from_place(&order, remaining, time);
            if self.incremental_on_apply {
                self.inc.upsert_resting(&resting);
                self.inc.set_next_time(self.next_time);
            }
            self.books
                .get_mut(&order.instrument)
                .expect("book")
                .insert(resting);
        }

        debug_assert!(
            !self.is_cross_owner_crossed(order.instrument),
            "book crossed across owners after place"
        );

        Receipt {
            outcome: Outcome::Accepted { remaining },
            fills,
            settlement,
            state_root: self.receipt_root(),
        }
    }

    fn cancel(&mut self, order_id: OrderId, owner: OwnerId, nonce: u64) -> Receipt {
        if let Err(r) = self.consume_nonce(owner, nonce) {
            return self.reject(r);
        }
        // Locate which book holds the order. Linear in number of markets (tiny).
        let found = self
            .books
            .iter()
            .find_map(|(inst, book)| book.get(order_id).map(|o| (*inst, o.owner, o.remaining)));
        let Some((inst, rest_owner, remaining)) = found else {
            return self.reject(RejectReason::UnknownOrder);
        };
        if rest_owner != owner {
            // Nonce already consumed. Order stays. This is harsh but deterministic;
            // a stolen nonce cannot cancel someone else's order.
            return self.reject(RejectReason::OwnerMismatch);
        }
        self.books.get_mut(&inst).expect("book").remove(order_id);
        if self.incremental_on_apply {
            self.inc.remove_resting(order_id);
        }
        self.metrics.cancels += 1;
        Receipt {
            outcome: Outcome::Cancelled {
                cancelled: remaining,
            },
            fills: Vec::new(),
            settlement: Vec::new(),
            state_root: self.receipt_root(),
        }
    }

    fn advance_height(&mut self, to: Height) -> Receipt {
        if to <= self.height {
            return self.reject(RejectReason::HeightNotMonotonic);
        }
        self.height = to;
        if self.incremental_on_apply {
            self.inc.set_height(to);
        }
        let mut expired = Vec::new();
        let inst_ids: Vec<InstrumentId> = self.books.keys().copied().collect();
        for inst in inst_ids {
            let ids = self
                .books
                .get(&inst)
                .expect("book")
                .collect_expired(self.height);
            for id in ids {
                self.books.get_mut(&inst).expect("book").remove(id);
                if self.incremental_on_apply {
                    self.inc.remove_resting(id);
                }
                expired.push(id);
            }
        }
        expired.sort();
        self.metrics.height_advances += 1;
        Receipt {
            outcome: Outcome::HeightAdvanced { expired },
            fills: Vec::new(),
            settlement: Vec::new(),
            state_root: self.receipt_root(),
        }
    }

    fn is_cross_owner_crossed(&self, inst: InstrumentId) -> bool {
        let Some(book) = self.books.get(&inst) else {
            return false;
        };
        let mut best_bid: Option<(Price, OwnerId)> = None;
        let mut best_ask: Option<(Price, OwnerId)> = None;
        book.visit_canonical(&mut |o| match o.side {
            Side::Buy => {
                if best_bid.is_none() {
                    best_bid = Some((o.price, o.owner));
                }
            }
            Side::Sell => {
                if best_ask.is_none() {
                    best_ask = Some((o.price, o.owner));
                }
            }
        });
        match (best_bid, best_ask) {
            (Some((bp, bo)), Some((ap, ao))) if bp.0 >= ap.0 && bo != ao => true,
            _ => false,
        }
    }
}

impl Engine<BTreeBook> {
    pub fn with_default_book(genesis: Genesis) -> Self {
        Self::new(genesis)
    }
}
