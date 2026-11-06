//! Malachite **application port** for M4a (ADR 0009).
//!
//! `Validate` replays `F` on a scratch engine and keeps it. Decide WALs `I`
//! and installs that engine (no third `F`). `I` is the sealed replicated
//! intent set (ADR 0016). Full-view replicas may share that set over
//! localhost TCP (ADR 0017). `RunningNode::offer` plus `gossip_spread`
//! (ADR 0018 / 0019) keeps the log alive past genesis without paying
//! Malachite `ready_delay` every height. After the first offer, admission
//! waits for every voter to ACK `id(set)` (ADR 0021). That is not world-computer
//! validity (no `π`).
//!
//! Engine: git-pinned Malachite `v0.8.0` via `app-channel` `EngineBuilder`.
//! Votes are on `id(v)` of [`protocol_types::ConsensusValue`], not a `u64`
//! test value and not an Engine API payload.
#![forbid(unsafe_code)]

mod cluster;
pub mod finality;
pub mod finality_net;
pub mod order_auth;
pub mod pq_tunnel;
pub mod engine;
mod intent_gossip;
mod intent_log;
pub mod limits;
mod node;
mod port;

pub use cluster::{run_height, Cluster, ClusterError};
pub use commitments::INPUT_DOMAIN;
pub use engine::{
    await_decisions, await_seal, percentile_ms, run_heights, start_cluster, start_four, AdmitPath,
    AdmitTrace, AppOpts, ClusterSpec, Decision, HeightSample, HeightSeal, RunningNode, ScaleRun,
};
pub use intent_log::{intent_id, IntentLog, INTENT_ID_DOMAIN, INTENT_SET_DOMAIN};
pub use node::{FullViewNode, NodeError};
pub use port::{
    check_height_statement, commit_list, height_statement, propose, validate, HeightStatementError,
    Validity,
};
