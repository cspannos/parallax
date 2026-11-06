//! End-to-end `π` pipeline (ADR 0028).
//!
//! A [`Follower`] is a FULL_VIEW replica that replays each decided height. For
//! every height it checks that its own `F` reproduces the decided value, then
//! emits an [`FJob`] (the `HeightStatement` plus the private snapshot and `I`)
//! into a [`JobDir`]. An external prover (`zkvm/risc0` `prover` binary) answers
//! with a receipt file. Settlement goes through `SettlementGate`, which only
//! moves money when the receipt verifies against the statement.
//!
//! The follower sees private state; it is a settlement operator's process, not
//! a light client. A light client needs only the statement and the receipt.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use clob::{BTreeBook, Engine, FJob};
use commitments::commit_list_payload;
use consensus_adapter::height_statement;
use protocol_types::{ConsensusValue, HeightStatement, Input, SettlementDelta};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PipelineError {
    #[error("height {0}: follower's F does not reproduce the decided value")]
    ValueMismatch(u64),
    #[error("height {got}: expected height {want}")]
    OutOfOrder { got: u64, want: u64 },
}

/// One decided height as the settlement side sees it.
#[derive(Clone, Debug)]
pub struct DecidedHeight {
    pub value: ConsensusValue,
    pub statement: HeightStatement,
    pub deltas: Vec<SettlementDelta>,
    pub job: FJob,
}

/// FULL_VIEW follower: replays decided `I`, emits `π` jobs.
pub struct Follower {
    engine: Engine<BTreeBook>,
    next_height: u64,
}

impl Follower {
    /// `engine` must equal the validators' state before height `first_height`
    /// (genesis plus any preload).
    pub fn new(engine: Engine<BTreeBook>, first_height: u64) -> Self {
        Self { engine, next_height: first_height }
    }

    pub fn engine(&self) -> &Engine<BTreeBook> {
        &self.engine
    }

    /// Replay one decided height. The statement is built from the follower's
    /// own pre-state and must bind the decided value; the snapshot is taken
    /// before applying `I`.
    pub fn on_decided(
        &mut self,
        value: &ConsensusValue,
        inputs: &[Input],
    ) -> Result<DecidedHeight, PipelineError> {
        let h = value.height.0;
        if h != self.next_height {
            return Err(PipelineError::OutOfOrder { got: h, want: self.next_height });
        }
        let statement = height_statement(&self.engine, value.parent, value.height, inputs);
        if !statement.binds_value(value) {
            return Err(PipelineError::ValueMismatch(h));
        }
        let job = FJob {
            statement: statement.clone(),
            snapshot: self.engine.snapshot().encode(),
            inputs: commit_list_payload(inputs),
        };
        let deltas = self
            .engine
            .apply_all(inputs.iter().cloned())
            .into_iter()
            .flat_map(|r| r.settlement)
            .collect();
        self.next_height += 1;
        Ok(DecidedHeight { value: value.clone(), statement, deltas, job })
    }
}

/// Shared directory between the follower and an external prover:
/// `jobs/<height>.job` in, `receipts/<height>.receipt` out. Writes are
/// tmp-then-rename, so a reader never sees a partial file.
#[derive(Clone, Debug)]
pub struct JobDir {
    root: PathBuf,
}

impl JobDir {
    pub fn create(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("jobs"))?;
        std::fs::create_dir_all(root.join("receipts"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn name(height: u64) -> String {
        format!("{height:010}")
    }

    pub fn write_job(&self, job: &FJob) -> std::io::Result<PathBuf> {
        let name = Self::name(job.statement.height.0);
        let tmp = self.root.join("jobs").join(format!(".{name}.tmp"));
        let path = self.root.join("jobs").join(format!("{name}.job"));
        std::fs::write(&tmp, job.encode())?;
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// The receipt for `height`, if the prover has written it.
    pub fn receipt(&self, height: u64) -> Option<Vec<u8>> {
        let path = self.root.join("receipts").join(format!("{}.receipt", Self::name(height)));
        std::fs::read(path).ok()
    }

    /// The image ID file the prover writes at start (`receipts/f_guest.id`).
    /// A deployment pins this in configuration instead of trusting the prover.
    pub fn image_id(&self) -> Option<[u32; 8]> {
        let b = std::fs::read(self.root.join("receipts").join("f_guest.id")).ok()?;
        (b.len() == 32).then(|| {
            std::array::from_fn(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::{btree_engine, churn_wave, load_places};
    use clob::run_f;
    use consensus_adapter::propose;

    /// Native end-to-end without a prover: the follower's jobs prove (natively)
    /// exactly the statements the validators decided.
    #[test]
    fn follower_jobs_match_decided_statements() {
        let mut validator = btree_engine();
        validator.apply_all(load_places(20));
        let mut follower = Follower::new(validator.clone(), 1);
        let mut parent = ConsensusValue::GENESIS_PARENT;
        for h in 1..=4u64 {
            let inputs = churn_wave(20, 8, h);
            let value = propose(&validator, parent, protocol_types::Height(h), &inputs);
            validator.apply_all(inputs.clone());
            let d = follower.on_decided(&value, &inputs).expect("follow");
            assert_eq!(d.value.state_root, validator.state_root().to_bytes32());
            let claim = run_f(&d.job.snapshot, &d.job.inputs).expect("F");
            assert!(d.job.journal_matches(&claim.to_bytes()), "height {h}");
            assert_eq!(FJob::decode(&d.job.encode()), Some(d.job.clone()));
            parent = commitments::value_id(&value).to_bytes32();
        }
    }

    #[test]
    fn follower_rejects_a_value_it_cannot_reproduce() {
        let validator = btree_engine();
        let mut follower = Follower::new(validator.clone(), 1);
        let inputs = churn_wave(1, 4, 0);
        let mut value = propose(&validator, ConsensusValue::GENESIS_PARENT, protocol_types::Height(1), &inputs);
        value.state_root.0[0] ^= 1;
        assert_eq!(follower.on_decided(&value, &inputs).err(), Some(PipelineError::ValueMismatch(1)));
        let ok = propose(&validator, ConsensusValue::GENESIS_PARENT, protocol_types::Height(2), &inputs);
        assert!(matches!(follower.on_decided(&ok, &inputs), Err(PipelineError::OutOfOrder { .. })));
    }

    #[test]
    fn job_dir_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let jobs = JobDir::create(dir.path()).unwrap();
        assert_eq!(jobs.receipt(1), None);
        std::fs::write(dir.path().join("receipts/0000000001.receipt"), b"r").unwrap();
        assert_eq!(jobs.receipt(1), Some(b"r".to_vec()));
    }
}
