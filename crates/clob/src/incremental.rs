//! Incremental book/nonce/seen commitment — consensus `C'` (ADR 0013).
//!
//! Domain `INC_DOMAIN` (`plx/clob/inc/v1`). The O(n) walk (`full_walk_root`)
//! remains for matcher benches and as a cross-check; it is not `id(v)`.

use std::cell::RefCell;

use commitments::{
    HashedMap, IncHeader, StateHasher, StateRoot, TreapHash, TreapStep, INC_DOMAIN, MAP_NONCES,
    MAP_RESTING, MAP_SEEN,
};
use protocol_types::{
    CanonicalEncode, Height, Instrument, OrderId, OwnerId, TimeSeq, ENCODING_VERSION,
};

use crate::book::RestingOrder;

thread_local! {
    static STEP_TRACE: RefCell<Option<Vec<(u8, TreapStep)>>> = const { RefCell::new(None) };
}

/// Record a [`TreapStep`] witness for every map mutation until
/// [`take_inc_step_trace`]. Prove-witness only; costs one extra path walk.
pub fn start_inc_step_trace() {
    STEP_TRACE.with(|t| *t.borrow_mut() = Some(Vec::new()));
}

/// Take and stop the [`start_inc_step_trace`] buffer: `(map, step)` in apply order.
pub fn take_inc_step_trace() -> Vec<(u8, TreapStep)> {
    STEP_TRACE.with(|t| t.borrow_mut().take().unwrap_or_default())
}

fn record(map: u8, step: impl FnOnce() -> TreapStep) {
    STEP_TRACE.with(|t| {
        if let Some(buf) = t.borrow_mut().as_mut() {
            buf.push((map, step()));
        }
    });
}

#[derive(Clone, Debug)]
pub struct IncrementalState {
    height: Height,
    next_time: TimeSeq,
    instruments: StateRoot,
    nonces: HashedMap,
    seen: HashedMap,
    resting: HashedMap,
    hash: TreapHash,
}

impl IncrementalState {
    pub fn new(height: Height, instruments: impl Iterator<Item = Instrument>) -> Self {
        Self::with_hash(height, instruments, TreapHash::default())
    }

    pub fn with_hash(
        height: Height,
        instruments: impl Iterator<Item = Instrument>,
        hash: TreapHash,
    ) -> Self {
        let mut h = StateHasher::with_domain(INC_DOMAIN);
        h.tag(b"instrs");
        let mut specs: Vec<Instrument> = instruments.collect();
        specs.sort_by_key(|s| s.id);
        for spec in &specs {
            h.write_encoded(spec);
        }
        Self {
            height,
            next_time: TimeSeq(0),
            instruments: h.finalize(),
            nonces: HashedMap::with_hash(hash),
            seen: HashedMap::with_hash(hash),
            resting: HashedMap::with_hash(hash),
            hash,
        }
    }

    /// Bulk build from canonical fields (one hash per entry, see
    /// [`HashedMap::from_sorted`]). Same root as upserting them one by one.
    /// `nonces` / `seen` / `resting` must each be strictly increasing by key
    /// (`resting` by order id).
    pub fn from_parts<'a>(
        height: Height,
        instruments: impl Iterator<Item = Instrument>,
        hash: TreapHash,
        next_time: TimeSeq,
        nonces: impl Iterator<Item = (OwnerId, u64)>,
        seen: impl Iterator<Item = OrderId>,
        resting: impl Iterator<Item = &'a RestingOrder>,
    ) -> Self {
        let mut s = Self::with_hash(height, instruments, hash);
        s.next_time = next_time;
        s.nonces = HashedMap::from_sorted(hash, nonces.map(|(o, n)| (o.encode_vec(), n.encode_vec())));
        s.seen = HashedMap::from_sorted(hash, seen.map(|id| (id.encode_vec(), Vec::new())));
        s.resting = HashedMap::from_sorted(hash, resting.map(|o| (o.id.encode_vec(), o.leaf_bytes())));
        s.flush();
        s
    }

    /// Hash pending lazy treap changes (ADR 0032) so roots read for free.
    pub fn flush(&mut self) {
        self.nonces.flush();
        self.seen.flush();
        self.resting.flush();
    }

    pub fn root(&self) -> StateRoot {
        if self.hash == TreapHash::Sha256 {
            let maps = [self.nonces.root(), self.seen.root(), self.resting.root()];
            return commitments::inc_root_with(TreapHash::Sha256, &self.inc_header(), &maps);
        }
        let mut h = StateHasher::with_domain(INC_DOMAIN);
        h.tag(b"height");
        h.write_encoded(&self.height);
        h.tag(b"next_t");
        h.write_encoded(&self.next_time);
        h.tag(b"instrs");
        h.write_encoded(&self.instruments);
        h.tag(b"nonces");
        h.write_encoded(&self.nonces.root());
        h.tag(b"seenid");
        h.write_encoded(&self.seen.root());
        h.tag(b"books");
        h.write_encoded(&self.resting.root());
        h.finalize()
    }

    /// Concatenation hashed by [`Self::root`]. Not a `node_digest`.
    pub fn root_preimage(&self) -> Vec<u8> {
        fn push_encoded(pre: &mut Vec<u8>, value: &impl CanonicalEncode) {
            let bytes = value.encode_vec();
            pre.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            pre.extend_from_slice(&bytes);
        }
        let mut pre = Vec::new();
        pre.extend_from_slice(INC_DOMAIN);
        pre.extend_from_slice(&ENCODING_VERSION.to_le_bytes());
        pre.extend_from_slice(b"height");
        push_encoded(&mut pre, &self.height);
        pre.extend_from_slice(b"next_t");
        push_encoded(&mut pre, &self.next_time);
        pre.extend_from_slice(b"instrs");
        push_encoded(&mut pre, &self.instruments);
        pre.extend_from_slice(b"nonces");
        push_encoded(&mut pre, &self.nonces.root());
        pre.extend_from_slice(b"seenid");
        push_encoded(&mut pre, &self.seen.root());
        pre.extend_from_slice(b"books");
        push_encoded(&mut pre, &self.resting.root());
        pre
    }

    pub fn set_height(&mut self, height: Height) {
        self.height = height;
    }

    pub fn set_next_time(&mut self, next_time: TimeSeq) {
        self.next_time = next_time;
    }

    pub fn upsert_nonce(&mut self, owner: OwnerId, nonce: u64) {
        let (key, value) = (owner.encode_vec(), nonce.encode_vec());
        record(MAP_NONCES, || self.nonces.upsert_step(&key, &value));
        self.nonces.upsert(&key, &value);
    }

    pub fn note_seen(&mut self, id: OrderId) {
        let key = id.encode_vec();
        record(MAP_SEEN, || self.seen.upsert_step(&key, &[]));
        self.seen.upsert(&key, &[]);
    }

    pub fn upsert_resting(&mut self, order: &RestingOrder) {
        let (key, value) = (order.id.encode_vec(), order.leaf_bytes());
        record(MAP_RESTING, || self.resting.upsert_step(&key, &value));
        self.resting.upsert(&key, &value);
    }

    pub fn remove_resting(&mut self, id: OrderId) {
        let key = id.encode_vec();
        record(MAP_RESTING, || self.resting.remove_step(&key));
        self.resting.remove(&key);
    }

    /// Non-map INC fields, as [`commitments::inc_root`] takes them.
    pub fn inc_header(&self) -> IncHeader {
        IncHeader {
            height: self.height.0,
            next_time: self.next_time.0,
            instruments: self.instruments,
        }
    }

    pub fn resting_len(&self) -> usize {
        self.resting.len()
    }

    pub fn height(&self) -> Height {
        self.height
    }

    pub fn next_time(&self) -> TimeSeq {
        self.next_time
    }

    pub fn instruments_root(&self) -> StateRoot {
        self.instruments
    }

    /// `(nonces, seen, resting)` treap roots. Not `C'`.
    pub fn map_roots(&self) -> (StateRoot, StateRoot, StateRoot) {
        (self.nonces.root(), self.seen.root(), self.resting.root())
    }
}
