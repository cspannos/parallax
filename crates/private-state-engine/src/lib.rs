//! Private State Engine — CLOB only (M1).
#![forbid(unsafe_code)]

//!
//! `apply` is `F`. The returned `state_root` is a commitment, not a proof.

pub use clob::{
    BTreeBook, Book, Engine, Genesis, Metrics, Outcome, Receipt, RejectReason, RestingOrder,
    VecBook,
};
pub use commitments::{Digest, StateRoot};
pub use protocol_types::{
    AssetId, Fill, Height, Input, Instrument, InstrumentId, Order, OrderId, OwnerId, Price, Qty,
    SettlementDelta, Side, TimeSeq,
};

/// Named apply API for Phase 2 replicas. Identical to [`Engine::apply`].
pub type PrivateStateEngine<B = BTreeBook> = Engine<B>;
