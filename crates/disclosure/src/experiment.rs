//! Four-node experiment. One full snapshot, four labelled projections.

use crate::capability::Capability;
use crate::predicate::{evaluate, prevote, Judgment, Mode, Predicate, Prevote};
use crate::snapshot::{FullSnapshot, PublicBundle};
use crate::view::{project, VisibleSnapshot};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeReport {
    pub capability: Capability,
    pub bundle: PublicBundle,
    pub honest_prevote: Prevote,
    pub naive_prevote: Prevote,
    pub honest: PredicateRow,
    pub naive: PredicateRow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PredicateRow {
    pub binding: Judgment,
    pub matching: Judgment,
    pub stp: Judgment,
    pub authorization: Judgment,
    pub settlement: Judgment,
    pub compliance: Judgment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentReport {
    pub bundle: PublicBundle,
    pub nodes: Vec<NodeReport>,
}

impl ExperimentReport {
    pub fn node(&self, cap: Capability) -> &NodeReport {
        self.nodes
            .iter()
            .find(|n| n.capability == cap)
            .expect("m3 node")
    }

    /// Same announced `C'`, honest FULL_VIEW Valid, naive TRADING_VIEW Invalid.
    pub fn same_c_disagreement_on_validity(&self) -> bool {
        let a = self.node(Capability::FullView);
        let b = self.node(Capability::TradingView);
        a.bundle == b.bundle
            && a.honest_prevote == Prevote::Valid
            && b.naive_prevote == Prevote::Invalid
            && b.honest_prevote == Prevote::InsufficientView
    }
}

pub fn run() -> ExperimentReport {
    let full = FullSnapshot::m3();
    let bundle = PublicBundle::from_full(&full);
    let nodes = Capability::M3_NODES
        .into_iter()
        .map(|cap| {
            let view = project(cap, &full);
            node_report(cap, &full, bundle, &view)
        })
        .collect();
    ExperimentReport { bundle, nodes }
}

fn node_report(
    cap: Capability,
    full: &FullSnapshot,
    bundle: PublicBundle,
    view: &VisibleSnapshot,
) -> NodeReport {
    let honest = row(cap, Mode::Honest, full, &bundle, view);
    let naive = row(cap, Mode::Naive, full, &bundle, view);
    NodeReport {
        capability: cap,
        bundle,
        honest_prevote: prevote(cap, Mode::Honest, full, &bundle, view),
        naive_prevote: prevote(cap, Mode::Naive, full, &bundle, view),
        honest,
        naive,
    }
}

fn row(
    cap: Capability,
    mode: Mode,
    full: &FullSnapshot,
    bundle: &PublicBundle,
    view: &VisibleSnapshot,
) -> PredicateRow {
    PredicateRow {
        binding: evaluate(
            Predicate::BindingToAnnouncedRoot,
            cap,
            mode,
            full,
            bundle,
            view,
        ),
        matching: evaluate(Predicate::MatchingPriceTime, cap, mode, full, bundle, view),
        stp: evaluate(
            Predicate::SelfTradePrevention,
            cap,
            mode,
            full,
            bundle,
            view,
        ),
        authorization: evaluate(Predicate::OwnerAuthorization, cap, mode, full, bundle, view),
        settlement: evaluate(
            Predicate::SettlementImpliedByFills,
            cap,
            mode,
            full,
            bundle,
            view,
        ),
        compliance: evaluate(
            Predicate::ComplianceConstraints,
            cap,
            mode,
            full,
            bundle,
            view,
        ),
    }
}
