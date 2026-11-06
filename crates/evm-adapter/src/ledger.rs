//! Privileged settlement ledger. Not the CLOB. Not Reth MDBX.

use std::collections::BTreeMap;

use commitments::{Digest, EVM_STATE_DOMAIN};
use protocol_types::{AssetId, Bytes32, CanonicalEncode, EncodeBuf, OwnerId, SettlementDelta};

#[derive(Clone, Debug, Default)]
pub struct Ledger {
    /// `(asset, account)` so the walk is deterministic.
    balances: BTreeMap<(AssetId, OwnerId), u128>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn genesis_fund(&mut self, account: OwnerId, asset: AssetId, amount: u128) {
        if amount == 0 {
            return;
        }
        self.balances
            .entry((asset, account))
            .and_modify(|b| *b = b.saturating_add(amount))
            .or_insert(amount);
    }

    pub fn balance(&self, account: OwnerId, asset: AssetId) -> u128 {
        self.balances.get(&(asset, account)).copied().unwrap_or(0)
    }

    /// One batch = one privileged apply (not one tx per delta).
    pub fn apply_batch(&mut self, deltas: &[SettlementDelta]) -> Result<(), LedgerError> {
        let mut next = self.balances.clone();
        for d in deltas {
            let key = (d.asset, d.account);
            let cur = next.get(&key).copied().unwrap_or(0);
            let new = if d.debit {
                cur.checked_sub(d.amount)
                    .ok_or(LedgerError::InsufficientBalance)?
            } else {
                cur.checked_add(d.amount).ok_or(LedgerError::Overflow)?
            };
            if new == 0 {
                next.remove(&key);
            } else {
                next.insert(key, new);
            }
        }
        self.balances = next;
        Ok(())
    }

    pub fn state_root(&self) -> Bytes32 {
        let mut buf = EncodeBuf::new();
        buf.u32(self.balances.len() as u32);
        for ((asset, account), amount) in &self.balances {
            asset.encode(&mut buf);
            account.encode(&mut buf);
            buf.u128(*amount);
        }
        Digest::from_bytes(buf.as_slice(), EVM_STATE_DOMAIN).to_bytes32()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("debit exceeds balance")]
    InsufficientBalance,
    #[error("credit overflow")]
    Overflow,
}
