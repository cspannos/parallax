//! Canonical protocol types for Parallax native execution.
//!
//! M1 exposes only CLOB-relevant types. Encoding is hand-written little-endian.
//! There is no serde on the consensus-critical path.
#![forbid(unsafe_code)]

mod codec;
mod consensus_value;
mod decode;
mod height_statement;
mod ids;
mod instrument;
mod order;
mod qty;
mod settlement;
mod suite;

pub use codec::{CanonicalEncode, EncodeBuf, ENCODING_VERSION};
pub use consensus_value::ConsensusValue;
pub use decode::{CanonicalDecode, DecodeBuf, DecodeError, GenesisBlob};
pub use height_statement::HeightStatement;
pub use ids::{AssetId, Bytes32, InstrumentId, OrderId, OwnerId};
pub use instrument::Instrument;
pub use order::{Height, Order, Side, TimeSeq};
pub use qty::{notional, Price, Qty};
pub use settlement::{Fill, SettlementDelta};
pub use suite::{AlgorithmId, CryptoSuiteId};

/// Input to the private state engine. This is the ordered `I` in `S' = F(S, I)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Place(Order),
    Cancel {
        order_id: OrderId,
        owner: OwnerId,
        nonce: u64,
    },
    /// Must be strictly greater than the current engine height.
    AdvanceHeight {
        to: Height,
    },
}

impl CanonicalEncode for Input {
    fn encode(&self, buf: &mut EncodeBuf) {
        match self {
            Self::Place(order) => {
                buf.tag(*b"INPLACE\0");
                order.encode(buf);
            }
            Self::Cancel {
                order_id,
                owner,
                nonce,
            } => {
                buf.tag(*b"INCNCL\0\0");
                order_id.encode(buf);
                owner.encode(buf);
                buf.u64(*nonce);
            }
            Self::AdvanceHeight { to } => {
                buf.tag(*b"INADVH\0\0");
                to.encode(buf);
            }
        }
    }
}
