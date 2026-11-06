use protocol_types::{
    CanonicalEncode, Height, InstrumentId, Order, OrderId, OwnerId, Price, Qty, Side, TimeSeq,
};

/// Resting remainder of a limit order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestingOrder {
    pub id: OrderId,
    pub instrument: InstrumentId,
    pub side: Side,
    pub remaining: Qty,
    pub price: Price,
    pub owner: OwnerId,
    pub expiry: Height,
    pub nonce: u64,
    pub time: TimeSeq,
}

impl RestingOrder {
    pub fn encode_leaf(&self, buf: &mut protocol_types::EncodeBuf) {
        buf.tag(*b"RESTING\0");
        self.id.encode(buf);
        self.instrument.encode(buf);
        self.side.encode(buf);
        self.remaining.encode(buf);
        self.price.encode(buf);
        self.owner.encode(buf);
        self.expiry.encode(buf);
        buf.u64(self.nonce);
        self.time.encode(buf);
    }

    pub fn leaf_bytes(&self) -> Vec<u8> {
        // Exact size (103 B): one allocation instead of growing through ~4.
        let mut buf = protocol_types::EncodeBuf::with_capacity(103);
        self.encode_leaf(&mut buf);
        buf.into_vec()
    }

    pub fn from_place(order: &Order, remaining: Qty, time: TimeSeq) -> Self {
        Self {
            id: order.order_id,
            instrument: order.instrument,
            side: order.side,
            remaining,
            price: order.limit_price,
            owner: order.owner,
            expiry: order.expiry,
            nonce: order.nonce,
            time,
        }
    }
}

/// In-memory price-time book. Implementations must not iterate a `HashMap` when
/// producing canonical visits.
pub trait Book: Default {
    fn insert(&mut self, order: RestingOrder);
    fn remove(&mut self, id: OrderId) -> Option<RestingOrder>;
    fn get(&self, id: OrderId) -> Option<&RestingOrder>;
    fn contains(&self, id: OrderId) -> bool {
        self.get(id).is_some()
    }

    /// Reduce `id` by `qty`. Removes the order if remaining hits zero.
    /// `qty` must be > 0 and ≤ remaining.
    fn fill(&mut self, id: OrderId, qty: Qty) -> Option<RestingOrder>;

    /// First opposite-side order that crosses `limit` and is not `skip_owner`.
    fn best_cross(&self, taker: Side, limit: Price, skip_owner: OwnerId) -> Option<OrderId>;

    /// Bids high-to-low FIFO, then asks low-to-high FIFO.
    fn visit_canonical(&self, visit: &mut dyn FnMut(&RestingOrder));

    fn collect_expired(&self, height: Height) -> Vec<OrderId>;

    /// Capacity hint before a bulk rebuild ([`crate::Engine::from_snapshot`]).
    fn reserve(&mut self, _additional: usize) {}

    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub(crate) fn crosses(taker: Side, taker_limit: Price, maker_price: Price) -> bool {
    match taker {
        Side::Buy => taker_limit.0 >= maker_price.0,
        Side::Sell => taker_limit.0 <= maker_price.0,
    }
}
