//! Honest vs naive evaluation. Naive is the counterfactual, not a protocol.

use protocol_types::{Price, Side};

use crate::capability::Capability;
use crate::snapshot::{FullSnapshot, PublicBundle};
use crate::view::{VisibleResting, VisibleSnapshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Predicate {
    /// Recompute `C'` from full `S'` and compare to the public bundle.
    BindingToAnnouncedRoot,
    /// Price-time matching including STP. Needs owner + time + prices.
    MatchingPriceTime,
    /// Same-owner skip is consistent. Needs owner + side + price.
    SelfTradePrevention,
    /// Place/cancel nonce and owner. Needs owner + nonce + order id.
    OwnerAuthorization,
    /// Deltas implied by fills. Needs owners, prices, quantities.
    SettlementImpliedByFills,
    /// Jurisdiction / compliance metadata. Not on the M1 order.
    ComplianceConstraints,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgment {
    Holds,
    Fails,
    InsufficientView,
    /// Nobody has the fields, including `FULL_VIEW`.
    NotInSchema,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prevote {
    Valid,
    Invalid,
    InsufficientView,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// ADR 0005: if a required field is missing, do not pretend to Validate.
    Honest,
    /// Evaluate using only visible fields (missing owner ⇒ treat as distinct).
    /// Not a protocol; shows disagreement on the same `C'`.
    Naive,
}

pub fn evaluate(
    predicate: Predicate,
    cap: Capability,
    mode: Mode,
    full: &FullSnapshot,
    bundle: &PublicBundle,
    view: &VisibleSnapshot,
) -> Judgment {
    match predicate {
        Predicate::BindingToAnnouncedRoot => binding(cap, full, bundle),
        Predicate::MatchingPriceTime => matching(cap, mode, full, view),
        Predicate::SelfTradePrevention => stp(cap, mode, view),
        Predicate::OwnerAuthorization => authorization(cap, full),
        Predicate::SettlementImpliedByFills => settlement(cap, full),
        Predicate::ComplianceConstraints => Judgment::NotInSchema,
    }
}

fn binding(cap: Capability, full: &FullSnapshot, bundle: &PublicBundle) -> Judgment {
    if cap != Capability::FullView {
        return Judgment::InsufficientView;
    }
    if full.replay_root() == bundle.state_root && full.state_root == bundle.state_root {
        Judgment::Holds
    } else {
        Judgment::Fails
    }
}

fn matching(cap: Capability, mode: Mode, full: &FullSnapshot, view: &VisibleSnapshot) -> Judgment {
    match cap {
        Capability::FullView => {
            if full.replay_root() == full.state_root && !cross_owner_crossed(&view.resting) {
                Judgment::Holds
            } else {
                Judgment::Fails
            }
        }
        Capability::TradingView => match mode {
            Mode::Honest => Judgment::InsufficientView,
            Mode::Naive => {
                if naive_price_crossed(&view.resting) {
                    Judgment::Fails
                } else {
                    Judgment::Holds
                }
            }
        },
        Capability::PublicView | Capability::ComplianceView | Capability::SettlementView => {
            Judgment::InsufficientView
        }
    }
}

fn stp(cap: Capability, mode: Mode, view: &VisibleSnapshot) -> Judgment {
    match cap {
        Capability::FullView => {
            if self_crossed_same_owner(&view.resting) && !cross_owner_crossed(&view.resting) {
                Judgment::Holds
            } else if !cross_owner_crossed(&view.resting) {
                Judgment::Holds
            } else {
                Judgment::Fails
            }
        }
        Capability::TradingView => match mode {
            Mode::Honest => Judgment::InsufficientView,
            Mode::Naive => {
                if naive_price_crossed(&view.resting) {
                    Judgment::Fails
                } else {
                    Judgment::Holds
                }
            }
        },
        _ => Judgment::InsufficientView,
    }
}

fn authorization(cap: Capability, full: &FullSnapshot) -> Judgment {
    if cap != Capability::FullView {
        return Judgment::InsufficientView;
    }
    if full.replay_root() == full.state_root {
        Judgment::Holds
    } else {
        Judgment::Fails
    }
}

fn settlement(cap: Capability, full: &FullSnapshot) -> Judgment {
    if cap != Capability::FullView {
        return Judgment::InsufficientView;
    }
    let replayed = {
        let mut engine = clob::Engine::<clob::BTreeBook>::new(full.genesis.clone());
        engine.apply_all(full.inputs.iter().cloned())
    };
    let fills: Vec<_> = replayed
        .iter()
        .flat_map(|r| r.fills.iter())
        .cloned()
        .collect();
    let deltas: Vec<_> = replayed
        .iter()
        .flat_map(|r| r.settlement.iter())
        .cloned()
        .collect();
    if fills == full.fills && deltas == full.settlement {
        Judgment::Holds
    } else {
        Judgment::Fails
    }
}

pub fn prevote(
    cap: Capability,
    mode: Mode,
    full: &FullSnapshot,
    bundle: &PublicBundle,
    view: &VisibleSnapshot,
) -> Prevote {
    let binding = evaluate(
        Predicate::BindingToAnnouncedRoot,
        cap,
        mode,
        full,
        bundle,
        view,
    );
    let matching = evaluate(Predicate::MatchingPriceTime, cap, mode, full, bundle, view);
    let auth = evaluate(Predicate::OwnerAuthorization, cap, mode, full, bundle, view);

    match mode {
        Mode::Honest => {
            if binding == Judgment::Holds && matching == Judgment::Holds && auth == Judgment::Holds
            {
                Prevote::Valid
            } else if binding == Judgment::Fails
                || matching == Judgment::Fails
                || auth == Judgment::Fails
            {
                Prevote::Invalid
            } else {
                Prevote::InsufficientView
            }
        }
        Mode::Naive => {
            if matching == Judgment::Fails || binding == Judgment::Fails {
                Prevote::Invalid
            } else if matching == Judgment::Holds
                && binding == Judgment::Holds
                && auth == Judgment::Holds
            {
                Prevote::Valid
            } else {
                Prevote::InsufficientView
            }
        }
    }
}

fn naive_price_crossed(resting: &[VisibleResting]) -> bool {
    let mut best_bid: Option<Price> = None;
    let mut best_ask: Option<Price> = None;
    for o in resting {
        let (Some(side), Some(price)) = (o.side, o.price) else {
            continue;
        };
        match side {
            Side::Buy => {
                if best_bid.map(|b| price.0 > b.0).unwrap_or(true) {
                    best_bid = Some(price);
                }
            }
            Side::Sell => {
                if best_ask.map(|a| price.0 < a.0).unwrap_or(true) {
                    best_ask = Some(price);
                }
            }
        }
    }
    matches!((best_bid, best_ask), (Some(b), Some(a)) if b.0 >= a.0)
}

fn cross_owner_crossed(resting: &[VisibleResting]) -> bool {
    let mut best_bid: Option<(Price, protocol_types::OwnerId)> = None;
    let mut best_ask: Option<(Price, protocol_types::OwnerId)> = None;
    for o in resting {
        let (Some(side), Some(price), Some(owner)) = (o.side, o.price, o.owner) else {
            continue;
        };
        match side {
            Side::Buy => {
                if best_bid.is_none() {
                    best_bid = Some((price, owner));
                }
            }
            Side::Sell => {
                if best_ask.is_none() {
                    best_ask = Some((price, owner));
                }
            }
        }
    }
    match (best_bid, best_ask) {
        (Some((bp, bo)), Some((ap, ao))) if bp.0 >= ap.0 && bo != ao => true,
        _ => false,
    }
}

fn self_crossed_same_owner(resting: &[VisibleResting]) -> bool {
    naive_price_crossed(resting) && !cross_owner_crossed(resting)
}
