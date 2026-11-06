//! View taxonomy from `docs/privacy-model.md`.
//!
//! `FULL_VIEW` is the matching replica: every field the engine has, including
//! operational fields (id, time, nonce, expiry) that the table left implicit.
//! Other views receive **only** the fields named in that table. Missing named
//! fields (jurisdiction, compliance metadata) exist for nobody: they are not
//! on the M1 order (Q-ORD-1).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    FullView,
    TradingView,
    PublicView,
    ComplianceView,
    SettlementView,
}

impl Capability {
    /// The four Phase 3 validator roles (A–D). `SETTLEMENT_VIEW` is a fifth
    /// projection, not a consensus replica in M3.
    pub const M3_NODES: [Self; 4] = [
        Self::FullView,
        Self::TradingView,
        Self::PublicView,
        Self::ComplianceView,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::FullView => "FULL_VIEW",
            Self::TradingView => "TRADING_VIEW",
            Self::PublicView => "PUBLIC_VIEW",
            Self::ComplianceView => "COMPLIANCE_VIEW",
            Self::SettlementView => "SETTLEMENT_VIEW",
        }
    }
}
