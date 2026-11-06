//! Full snapshot and the public bundle every view is allowed to see.

use clob::{testutil, BTreeBook, Book, Engine, Genesis, Receipt, RestingOrder};
use commitments::{Digest, StateRoot, INPUT_DOMAIN, RECEIPT_DOMAIN};
use protocol_types::{CanonicalEncode, EncodeBuf, Fill, Height, Input, SettlementDelta};

use crate::corpus::m3_stream;

#[derive(Clone, Debug)]
pub struct FullSnapshot {
    pub genesis: Genesis,
    pub inputs: Vec<Input>,
    pub receipts: Vec<Receipt>,
    pub fills: Vec<Fill>,
    pub settlement: Vec<SettlementDelta>,
    pub resting: Vec<RestingOrder>,
    pub height: Height,
    pub state_root: StateRoot,
}

impl FullSnapshot {
    pub fn capture(genesis: Genesis, inputs: Vec<Input>) -> Self {
        let mut engine = Engine::<BTreeBook>::new(genesis.clone());
        let receipts: Vec<Receipt> = inputs.iter().cloned().map(|i| engine.apply(i)).collect();
        let fills = receipts
            .iter()
            .flat_map(|r| r.fills.iter().cloned())
            .collect();
        let settlement = receipts
            .iter()
            .flat_map(|r| r.settlement.iter().cloned())
            .collect();
        let mut resting = Vec::new();
        for spec in &genesis.instruments {
            if let Some(book) = engine.book(spec.id) {
                book.visit_canonical(&mut |o| resting.push(o.clone()));
            }
        }
        Self {
            genesis,
            inputs,
            receipts,
            fills,
            settlement,
            resting,
            height: engine.height(),
            state_root: engine.state_root(),
        }
    }

    /// Default M3 market + corpus.
    pub fn m3() -> Self {
        Self::capture(testutil::genesis(), m3_stream())
    }

    /// Re-run `F` on a fresh engine. Full-view binding + matching gold standard.
    pub fn replay_root(&self) -> StateRoot {
        let mut engine = Engine::<BTreeBook>::new(self.genesis.clone());
        engine.apply_all(self.inputs.iter().cloned());
        engine.state_root()
    }
}

/// Bytes the privacy model calls `PUBLIC_VIEW`. No order plaintext. No `π`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicBundle {
    pub height: Height,
    pub state_root: StateRoot,
    pub input_commitment: Digest,
    pub settlement_commitment: Digest,
}

impl PublicBundle {
    pub fn from_full(full: &FullSnapshot) -> Self {
        Self {
            height: full.height,
            state_root: full.state_root,
            input_commitment: commit_list(&full.inputs, INPUT_DOMAIN),
            settlement_commitment: commit_list(&full.settlement, RECEIPT_DOMAIN),
        }
    }
}

pub fn commit_list<T: CanonicalEncode>(items: &[T], domain: &[u8]) -> Digest {
    let mut buf = EncodeBuf::new();
    buf.u32(items.len() as u32);
    for item in items {
        item.encode(&mut buf);
    }
    Digest::from_bytes(buf.as_slice(), domain)
}
