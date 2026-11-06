//! One full-view replica + last decided `id(v)`.

use std::collections::BTreeMap;
use std::path::Path;

use clob::{BTreeBook, Engine, Genesis};
use commitments::{value_id, Digest, INPUT_DOMAIN, RECEIPT_DOMAIN};
use protocol_types::{Bytes32, ConsensusValue, Height, Input, SettlementDelta};
use replica::{Replica, ReplicaError, ReplicaOpts, SyncMode};

use crate::port::{commit_list, replay, Validity};

#[derive(Debug)]
pub enum NodeError {
    Replica(ReplicaError),
    AlreadyDecided,
    NotValid,
}

impl From<ReplicaError> for NodeError {
    fn from(e: ReplicaError) -> Self {
        Self::Replica(e)
    }
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replica(e) => write!(f, "{e}"),
            Self::AlreadyDecided => write!(f, "height already decided"),
            Self::NotValid => write!(f, "cannot decide an invalid value"),
        }
    }
}

impl std::error::Error for NodeError {}

pub struct FullViewNode {
    replica: Replica,
    last_id: Bytes32,
    last_height: u64,
    decided: BTreeMap<u64, Digest>,
    /// Scratch from GetValue, speculative `I`, or Validate, keyed by the value.
    pending: Option<(ConsensusValue, Engine<BTreeBook>)>,
}

impl FullViewNode {
    pub fn open(wal: impl AsRef<Path>, key: [u8; 32], genesis: Genesis) -> Result<Self, NodeError> {
        Self::open_with(wal, key, genesis, SyncMode::Full)
    }

    pub fn open_with(
        wal: impl AsRef<Path>,
        key: [u8; 32],
        genesis: Genesis,
        sync: SyncMode,
    ) -> Result<Self, NodeError> {
        let mut opts = ReplicaOpts::new(wal, key, genesis);
        opts.sync = sync;
        let (replica, _) = Replica::open(opts)?;
        Ok(Self {
            replica,
            last_id: ConsensusValue::GENESIS_PARENT,
            last_height: 0,
            decided: BTreeMap::new(),
            pending: None,
        })
    }

    /// WAL + `F` without a consensus height. Loads a book before `GetValue`.
    pub fn preload(&mut self, inputs: &[Input]) -> Result<(), NodeError> {
        self.replica.submit_batch(inputs.iter().cloned())?;
        Ok(())
    }

    pub fn replica(&self) -> &Replica {
        &self.replica
    }

    pub fn next_height(&self) -> Height {
        Height(self.last_height + 1)
    }

    pub fn last_id(&self) -> Bytes32 {
        self.last_id
    }

    pub fn decided_id(&self, height: u64) -> Option<Digest> {
        self.decided.get(&height).copied()
    }

    /// Scratch-apply local `I` before a proposal arrives (shared-`I` / Model I).
    /// No-op if a scratch for this height already exists. Does not license
    /// proposer-packed `I` (Q-CONS-10).
    pub fn speculate(&mut self, inputs: &[Input]) {
        if self
            .pending
            .as_ref()
            .is_some_and(|(v, _)| v.parent == self.last_id && v.height == self.next_height())
        {
            return;
        }
        let _ = self.get_value(inputs);
    }

    /// `GetValue`. Keeps the scratch engine for decide (WAL `I`, no second `F`).
    /// Reuses a speculative scratch when `I` matches.
    pub fn get_value(&mut self, inputs: &[Input]) -> ConsensusValue {
        let input_c = commit_list(inputs, INPUT_DOMAIN);
        if let Some((v, _)) = &self.pending {
            if v.parent == self.last_id
                && v.height == self.next_height()
                && v.input_commitment == input_c.to_bytes32()
            {
                return *v;
            }
        }
        let r = replay(
            self.replica.engine(),
            self.last_id,
            self.next_height(),
            inputs,
        );
        self.pending = Some((r.value, r.engine));
        r.value
    }

    /// Proposal `Validate` (prevote). `inputs == None` is withhold / missing fragments.
    ///
    /// Skips scratch `F` when GetValue or a speculative apply already built this
    /// `id(v)`. Voters without a matching scratch still replay.
    pub fn validate_proposal(
        &mut self,
        value: &ConsensusValue,
        inputs: Option<&[Input]>,
    ) -> Validity {
        if value.parent != self.last_id || value.height != self.next_height() {
            return Validity::Invalid;
        }
        let Some(inputs) = inputs else {
            return Validity::InsufficientView;
        };
        let id = value_id(value);
        if self
            .pending
            .as_ref()
            .is_some_and(|(pv, _)| value_id(pv) == id)
        {
            let input_c = commit_list(inputs, INPUT_DOMAIN);
            if value.input_commitment != input_c.to_bytes32() {
                return Validity::Invalid;
            }
            return Validity::Valid;
        }
        let r = replay(
            self.replica.engine(),
            self.last_id,
            self.next_height(),
            inputs,
        );
        if value.state_root != r.value.state_root
            || value.input_commitment != r.value.input_commitment
            || value.settlement_commitment != r.value.settlement_commitment
        {
            return Validity::Invalid;
        }
        self.pending = Some((r.value, r.engine));
        Validity::Valid
    }

    /// Persist `I` and lock the height.
    ///
    /// If GetValue/Validate already produced this `id(v)`, WAL the tape and
    /// install that engine (no third `F`). Otherwise `submit_batch` (apply).
    /// Cheap parent / height / `input_commitment` checks always run first.
    pub fn decide(
        &mut self,
        value: &ConsensusValue,
        inputs: &[Input],
    ) -> Result<Digest, NodeError> {
        let h = value.height.0;
        if self.decided.contains_key(&h) {
            return Err(NodeError::AlreadyDecided);
        }
        if value.parent != self.last_id || value.height != self.next_height() {
            return Err(NodeError::NotValid);
        }
        let input_c = commit_list(inputs, INPUT_DOMAIN);
        if value.input_commitment != input_c.to_bytes32() {
            return Err(NodeError::NotValid);
        }
        let id = value_id(value);
        let reuse = self.pending.take().filter(|(pv, _)| value_id(pv) == id);
        if let Some((_, engine)) = reuse {
            self.replica.persist_batch(inputs.iter().cloned())?;
            self.replica.install_engine(engine);
            if value.state_root != self.replica.state_root().to_bytes32() {
                return Err(NodeError::NotValid);
            }
        } else {
            let receipts = self.replica.submit_batch(inputs.iter().cloned())?;
            let settlement: Vec<SettlementDelta> = receipts
                .iter()
                .flat_map(|r| r.settlement.iter().cloned())
                .collect();
            let sett_c = commit_list(&settlement, RECEIPT_DOMAIN);
            if value.state_root != self.replica.state_root().to_bytes32()
                || value.settlement_commitment != sett_c.to_bytes32()
            {
                return Err(NodeError::NotValid);
            }
        }
        self.decided.insert(h, id);
        self.last_id = id.to_bytes32();
        self.last_height = h;
        Ok(id)
    }
}
