use crate::codec::{CanonicalEncode, EncodeBuf};
use crate::ids::{AssetId, OrderId, OwnerId};
use crate::qty::{Price, Qty};

/// One matched quantity at the maker's price.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fill {
    pub taker_order_id: OrderId,
    pub maker_order_id: OrderId,
    pub taker: OwnerId,
    pub maker: OwnerId,
    pub qty: Qty,
    pub price: Price,
}

impl CanonicalEncode for Fill {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"FILL\0\0\0\0");
        self.taker_order_id.encode(buf);
        self.maker_order_id.encode(buf);
        self.taker.encode(buf);
        self.maker.encode(buf);
        self.qty.encode(buf);
        self.price.encode(buf);
    }
}

/// Signed asset delta. `debit == false` credits `amount`.
///
/// Magnitude is `u128` so a `u64×u64` notional always fits. `i128` does not
/// (see ADR 0006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementDelta {
    pub account: OwnerId,
    pub asset: AssetId,
    pub amount: u128,
    pub debit: bool,
}

impl SettlementDelta {
    pub fn credit(account: OwnerId, asset: AssetId, amount: u128) -> Self {
        Self {
            account,
            asset,
            amount,
            debit: false,
        }
    }

    pub fn debit(account: OwnerId, asset: AssetId, amount: u128) -> Self {
        Self {
            account,
            asset,
            amount,
            debit: true,
        }
    }
}

impl CanonicalEncode for SettlementDelta {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"DELTA\0\0\0");
        self.account.encode(buf);
        self.asset.encode(buf);
        buf.u128(self.amount);
        buf.u8(u8::from(self.debit));
    }
}
