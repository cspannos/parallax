//! Deterministic in-memory CLOB.
#![forbid(unsafe_code)]

//!
//! Matching is price/time (FIFO) at integer ticks. Two [`Book`] backends share
//! the same [`Engine`] so they can be compared for identical receipts and roots.

mod book;
mod btree_book;
mod engine;
mod id_hash;
mod incremental;
mod vec_book;

pub use book::{Book, RestingOrder};
pub use btree_book::BTreeBook;
pub use id_hash::{IdHashBuilder, IdHasher};
pub use commitments::{take_treap_hash_calls, HashedMap, TreapHash, TreapHashCalls};
pub use engine::{Engine, Genesis, Metrics, OrderIdRule, Outcome, Receipt, RejectReason};
pub use incremental::{start_inc_step_trace, take_inc_step_trace, IncrementalState};
pub use snapshot::{
    decode_inputs, run_f, EngineSnapshot, FClaim, FError, FJob, SnapshotError, F_CLAIM_BYTES,
    F_FLAGS_PRODUCTION,
};
pub use vec_book::VecBook;

pub mod snapshot;
pub mod testutil;
