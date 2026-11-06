//! Redaction. Absence is not a proof the field is empty.

use clob::RestingOrder;
use protocol_types::{
    CanonicalEncode, EncodeBuf, Fill, Height, InstrumentId, OrderId, OwnerId, Price, Qty, Side,
    TimeSeq,
};

use crate::capability::Capability;
use crate::snapshot::FullSnapshot;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleResting {
    pub id: Option<OrderId>,
    pub instrument: Option<InstrumentId>,
    pub side: Option<Side>,
    pub remaining: Option<Qty>,
    pub price: Option<Price>,
    pub owner: Option<OwnerId>,
    pub expiry: Option<Height>,
    pub nonce: Option<u64>,
    pub time: Option<TimeSeq>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleFill {
    pub taker_order_id: Option<OrderId>,
    pub maker_order_id: Option<OrderId>,
    pub taker: Option<OwnerId>,
    pub maker: Option<OwnerId>,
    pub qty: Option<Qty>,
    pub price: Option<Price>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleSnapshot {
    pub capability: Capability,
    pub resting: Vec<VisibleResting>,
    pub fills: Vec<VisibleFill>,
    pub settlement: Vec<protocol_types::SettlementDelta>,
}

impl VisibleSnapshot {
    pub fn contains_owner(&self, owner: OwnerId) -> bool {
        self.resting.iter().any(|o| o.owner == Some(owner))
            || self
                .fills
                .iter()
                .any(|f| f.taker == Some(owner) || f.maker == Some(owner))
            || self.settlement.iter().any(|d| d.account == owner)
    }
}

pub fn project(cap: Capability, full: &FullSnapshot) -> VisibleSnapshot {
    match cap {
        Capability::FullView => VisibleSnapshot {
            capability: cap,
            resting: full.resting.iter().map(full_resting).collect(),
            fills: full.fills.iter().map(full_fill).collect(),
            settlement: full.settlement.clone(),
        },
        Capability::TradingView => VisibleSnapshot {
            capability: cap,
            resting: full.resting.iter().map(trading_resting).collect(),
            fills: full.fills.iter().map(trading_fill).collect(),
            settlement: Vec::new(),
        },
        Capability::PublicView => VisibleSnapshot {
            capability: cap,
            resting: Vec::new(),
            fills: Vec::new(),
            settlement: Vec::new(),
        },
        Capability::ComplianceView => VisibleSnapshot {
            capability: cap,
            resting: full.resting.iter().map(compliance_resting).collect(),
            fills: full.fills.iter().map(compliance_fill).collect(),
            settlement: Vec::new(),
        },
        Capability::SettlementView => VisibleSnapshot {
            capability: cap,
            resting: Vec::new(),
            fills: Vec::new(),
            settlement: full.settlement.clone(),
        },
    }
}

fn full_resting(o: &RestingOrder) -> VisibleResting {
    VisibleResting {
        id: Some(o.id),
        instrument: Some(o.instrument),
        side: Some(o.side),
        remaining: Some(o.remaining),
        price: Some(o.price),
        owner: Some(o.owner),
        expiry: Some(o.expiry),
        nonce: Some(o.nonce),
        time: Some(o.time),
    }
}

fn trading_resting(o: &RestingOrder) -> VisibleResting {
    VisibleResting {
        id: None,
        instrument: Some(o.instrument),
        side: Some(o.side),
        remaining: Some(o.remaining),
        price: Some(o.price),
        owner: None,
        expiry: None,
        nonce: None,
        time: None,
    }
}

fn compliance_resting(o: &RestingOrder) -> VisibleResting {
    VisibleResting {
        id: None,
        instrument: Some(o.instrument),
        side: None,
        remaining: Some(o.remaining),
        price: None,
        owner: Some(o.owner),
        expiry: None,
        nonce: None,
        time: None,
    }
}

fn full_fill(f: &Fill) -> VisibleFill {
    VisibleFill {
        taker_order_id: Some(f.taker_order_id),
        maker_order_id: Some(f.maker_order_id),
        taker: Some(f.taker),
        maker: Some(f.maker),
        qty: Some(f.qty),
        price: Some(f.price),
    }
}

fn trading_fill(f: &Fill) -> VisibleFill {
    VisibleFill {
        taker_order_id: None,
        maker_order_id: None,
        taker: None,
        maker: None,
        qty: Some(f.qty),
        price: Some(f.price),
    }
}

fn compliance_fill(f: &Fill) -> VisibleFill {
    VisibleFill {
        taker_order_id: None,
        maker_order_id: None,
        taker: Some(f.taker),
        maker: Some(f.maker),
        qty: Some(f.qty),
        price: None,
    }
}

/// Canonical bytes of *visible* fields only. Used to test non-leakage, not as `C`.
impl CanonicalEncode for VisibleResting {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.tag(*b"VREST\0\0\0");
        encode_opt_id(buf, self.id);
        encode_opt_u32(buf, self.instrument.map(|i| i.0));
        match self.side {
            Some(s) => {
                buf.u8(1);
                s.encode(buf);
            }
            None => buf.u8(0),
        }
        encode_opt_u64(buf, self.remaining.map(|q| q.0));
        encode_opt_u64(buf, self.price.map(|p| p.0));
        match self.owner {
            Some(o) => {
                buf.u8(1);
                o.encode(buf);
            }
            None => buf.u8(0),
        }
        encode_opt_u64(buf, self.expiry.map(|h| h.0));
        encode_opt_u64(buf, self.nonce);
        encode_opt_u64(buf, self.time.map(|t| t.0));
    }
}

fn encode_opt_id(buf: &mut EncodeBuf, id: Option<OrderId>) {
    match id {
        Some(id) => {
            buf.u8(1);
            id.encode(buf);
        }
        None => buf.u8(0),
    }
}

fn encode_opt_u32(buf: &mut EncodeBuf, v: Option<u32>) {
    match v {
        Some(v) => {
            buf.u8(1);
            buf.u32(v);
        }
        None => buf.u8(0),
    }
}

fn encode_opt_u64(buf: &mut EncodeBuf, v: Option<u64>) {
    match v {
        Some(v) => {
            buf.u8(1);
            buf.u64(v);
        }
        None => buf.u8(0),
    }
}
