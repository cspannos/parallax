use crate::codec::{CanonicalEncode, EncodeBuf};
use crate::ids::{InstrumentId, OrderId, OwnerId};
use crate::qty::{Price, Qty};

/// Consensus height. Not wall clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Height(pub u64);

impl CanonicalEncode for Height {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u64(self.0);
    }
}

/// Monotonic rest sequence (time priority). Assigned by the engine, not the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TimeSeq(pub u64);

impl CanonicalEncode for TimeSeq {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u64(self.0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    pub fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Buy => 0,
            Self::Sell => 1,
        }
    }
}

impl CanonicalEncode for Side {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u8(self.as_u8());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub order_id: OrderId,
    pub instrument: InstrumentId,
    pub side: Side,
    pub quantity: Qty,
    pub limit_price: Price,
    pub owner: OwnerId,
    pub expiry: Height,
    pub nonce: u64,
}

impl CanonicalEncode for Order {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"ORDER\0\0\0");
        self.order_id.encode(buf);
        self.instrument.encode(buf);
        self.side.encode(buf);
        self.quantity.encode(buf);
        self.limit_price.encode(buf);
        self.owner.encode(buf);
        self.expiry.encode(buf);
        buf.u64(self.nonce);
    }
}
