//! Capability-labelled views of CLOB state.
//!
//! M3 answers whether unequal disclosure can share Malachite `valid(v)` without
//! a proof. Capabilities here are **access-control labels** on a projector that
//! already has full state (Q-DIS-1). They are not keys, IBE, or openings.
#![forbid(unsafe_code)]

mod capability;
mod corpus;
mod experiment;
mod predicate;
mod snapshot;
mod view;

pub use capability::Capability;
pub use corpus::m3_stream;
pub use experiment::{run, ExperimentReport, NodeReport};
pub use predicate::{evaluate, Judgment, Predicate, Prevote};
pub use snapshot::{commit_list, FullSnapshot, PublicBundle};
pub use view::{project, VisibleFill, VisibleResting, VisibleSnapshot};
