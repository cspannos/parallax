//! M3: four views of one height. Labels, not keys.

use clob::testutil::owner;
use commitments::Digest;
use disclosure::{project, run, Capability, FullSnapshot, Judgment, Prevote};
use protocol_types::CanonicalEncode;

#[test]
fn trading_does_not_receive_owner() {
    let full = FullSnapshot::m3();
    let view = project(Capability::TradingView, &full);
    let oid = owner(1);
    assert!(!view.contains_owner(oid));
    assert!(!view.contains_owner(owner(2)));
    assert!(!view.contains_owner(owner(3)));
    for rest in &view.resting {
        assert!(rest.owner.is_none());
        assert!(rest.time.is_none());
        assert!(rest.id.is_none());
        assert!(rest.price.is_some());
        assert!(rest.side.is_some());
    }
    let bytes = {
        let mut buf = protocol_types::EncodeBuf::new();
        for r in &view.resting {
            r.encode(&mut buf);
        }
        buf.into_vec()
    };
    assert!(
        !bytes.windows(32).any(|w| w == oid.0.as_slice()),
        "owner bytes leaked into trading encoding"
    );
}

#[test]
fn public_has_no_book_or_fills() {
    let full = FullSnapshot::m3();
    let view = project(Capability::PublicView, &full);
    assert!(view.resting.is_empty());
    assert!(view.fills.is_empty());
    assert!(view.settlement.is_empty());
}

#[test]
fn compliance_has_owner_not_price() {
    let full = FullSnapshot::m3();
    let view = project(Capability::ComplianceView, &full);
    assert!(view.contains_owner(owner(1)));
    for rest in &view.resting {
        assert!(rest.owner.is_some());
        assert!(rest.price.is_none());
        assert!(rest.side.is_none());
        assert!(rest.remaining.is_some());
    }
}

#[test]
fn hashing_a_redacted_view_is_not_c() {
    let full = FullSnapshot::m3();
    let view = project(Capability::TradingView, &full);
    let mut buf = protocol_types::EncodeBuf::new();
    for r in &view.resting {
        r.encode(&mut buf);
    }
    let fake = Digest::from_bytes(buf.as_slice(), b"not-a-protocol");
    assert_ne!(fake, full.state_root);
}

#[test]
fn four_nodes_share_the_same_public_bundle() {
    let report = run();
    for n in &report.nodes {
        assert_eq!(n.bundle, report.bundle);
    }
}

#[test]
fn q_cons_3_honest_prevote_is_full_view_only() {
    let report = run();
    assert_eq!(
        report.node(Capability::FullView).honest_prevote,
        Prevote::Valid
    );
    for cap in [
        Capability::TradingView,
        Capability::PublicView,
        Capability::ComplianceView,
    ] {
        assert_eq!(
            report.node(cap).honest_prevote,
            Prevote::InsufficientView,
            "{}",
            cap.name()
        );
    }
}

#[test]
fn same_c_trading_naive_invalid_full_valid() {
    let report = run();
    assert!(report.same_c_disagreement_on_validity());
    let trading = report.node(Capability::TradingView);
    assert_eq!(trading.naive.matching, Judgment::Fails);
    assert_eq!(trading.honest.matching, Judgment::InsufficientView);
}

#[test]
fn public_cannot_bind_or_match() {
    let report = run();
    let c = report.node(Capability::PublicView);
    assert_eq!(c.honest.binding, Judgment::InsufficientView);
    assert_eq!(c.honest.matching, Judgment::InsufficientView);
    assert_eq!(c.honest_prevote, Prevote::InsufficientView);
}

#[test]
fn compliance_constraints_not_in_schema() {
    let report = run();
    for n in &report.nodes {
        assert_eq!(n.honest.compliance, Judgment::NotInSchema);
    }
}

#[test]
fn corpus_has_a_real_fill_and_a_self_cross() {
    let full = FullSnapshot::m3();
    assert!(!full.fills.is_empty());
    assert!(full.resting.len() >= 2);
    let bids: Vec<_> = full
        .resting
        .iter()
        .filter(|o| o.side == protocol_types::Side::Buy)
        .collect();
    let asks: Vec<_> = full
        .resting
        .iter()
        .filter(|o| o.side == protocol_types::Side::Sell)
        .collect();
    assert!(bids.iter().any(|b| asks
        .iter()
        .any(|a| b.price.0 >= a.price.0 && b.owner == a.owner)));
}
