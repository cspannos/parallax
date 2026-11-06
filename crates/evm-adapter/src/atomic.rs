//! Two-phase apply log: intent then commit. Not the replica WAL.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use protocol_types::{
    Bytes32, CanonicalDecode, CanonicalEncode, ConsensusValue, DecodeBuf, EncodeBuf, Height,
    SettlementDelta,
};

use crate::sidecar::{InProcessSidecar, PayloadStatus, SettlementPayload, SidecarError};
use crate::Ledger;

const MAGIC: &[u8; 8] = b"PLXSET01";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettledHeight {
    pub height: u64,
    pub pse_root: Bytes32,
    pub evm_root: Bytes32,
    pub settlement_commitment: Bytes32,
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("settlement_commitment does not match deltas")]
    CommitmentMismatch,
    #[error("payload invalid: {0}")]
    InvalidPayload(&'static str),
    #[error(transparent)]
    Sidecar(#[from] SidecarError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("log decode")]
    LogCorrupt,
    #[error("simulated crash after intent")]
    SimulatedCrash,
}

pub fn settlement_commitment(deltas: &[SettlementDelta]) -> Bytes32 {
    let mut buf = EncodeBuf::new();
    buf.u32(deltas.len() as u32);
    for d in deltas {
        d.encode(&mut buf);
    }
    commitments::Digest::from_bytes(buf.as_slice(), commitments::RECEIPT_DOMAIN).to_bytes32()
}

pub struct AtomicApply {
    sidecar: InProcessSidecar,
    log_path: PathBuf,
    /// Test hook: return after intent WAL, before `new_payload`.
    pub crash_after_intent: bool,
    settled: Option<SettledHeight>,
}

impl AtomicApply {
    pub fn open(log: impl AsRef<Path>, ledger: Ledger) -> Result<Self, ApplyError> {
        let log_path = log.as_ref().to_path_buf();
        let sidecar = InProcessSidecar::new(ledger);
        let mut this = Self {
            sidecar,
            log_path,
            crash_after_intent: false,
            settled: None,
        };
        this.replay_committed()?;
        Ok(this)
    }

    pub fn settled(&self) -> Option<&SettledHeight> {
        self.settled.as_ref()
    }

    pub fn eth_get_balance(
        &self,
        account: protocol_types::OwnerId,
        asset: protocol_types::AssetId,
    ) -> u128 {
        self.sidecar.eth_get_balance(account, asset)
    }

    pub fn payload_count(&self) -> u64 {
        self.sidecar.payload_count()
    }

    pub fn sidecar_mut(&mut self) -> &mut InProcessSidecar {
        &mut self.sidecar
    }

    /// Finish a dangling intent after crash (idempotent apply).
    pub fn retry_pending(&mut self) -> Result<Option<SettledHeight>, ApplyError> {
        let Some((value, deltas)) = read_dangling_intent(&self.log_path)? else {
            return Ok(None);
        };
        self.finish_apply(value, deltas).map(Some)
    }

    pub fn apply_decided(
        &mut self,
        value: &ConsensusValue,
        deltas: &[SettlementDelta],
    ) -> Result<SettledHeight, ApplyError> {
        if settlement_commitment(deltas) != value.settlement_commitment {
            return Err(ApplyError::CommitmentMismatch);
        }
        append_intent(&self.log_path, value, deltas)?;
        if self.crash_after_intent {
            return Err(ApplyError::SimulatedCrash);
        }
        self.finish_apply(value.clone(), deltas.to_vec())
    }

    fn finish_apply(
        &mut self,
        value: ConsensusValue,
        deltas: Vec<SettlementDelta>,
    ) -> Result<SettledHeight, ApplyError> {
        let parent = self.sidecar.head();
        let status = self.sidecar.new_payload(SettlementPayload {
            parent_evm_root: parent,
            deltas,
        })?;
        let evm_root = match status {
            PayloadStatus::Syncing => {
                return Err(ApplyError::Sidecar(SidecarError::UnexpectedSyncing))
            }
            PayloadStatus::Invalid { validation_error } => {
                return Err(ApplyError::InvalidPayload(validation_error))
            }
            PayloadStatus::Valid { latest_valid_hash } => latest_valid_hash,
        };
        self.sidecar.forkchoice_updated(evm_root)?;
        append_commit(&self.log_path, value.height, evm_root)?;
        let settled = SettledHeight {
            height: value.height.0,
            pse_root: value.state_root,
            evm_root,
            settlement_commitment: value.settlement_commitment,
        };
        self.settled = Some(settled.clone());
        Ok(settled)
    }

    fn replay_committed(&mut self) -> Result<(), ApplyError> {
        let records = read_all(&self.log_path)?;
        let mut i = 0;
        while i < records.len() {
            match &records[i] {
                Rec::Intent { value, deltas } => {
                    if i + 1 < records.len() {
                        if let Rec::Commit { height, evm_root } = &records[i + 1] {
                            if *height == value.height {
                                let parent = self.sidecar.head();
                                let status = self.sidecar.new_payload(SettlementPayload {
                                    parent_evm_root: parent,
                                    deltas: deltas.clone(),
                                })?;
                                match status {
                                    PayloadStatus::Valid { latest_valid_hash } => {
                                        if latest_valid_hash != *evm_root {
                                            return Err(ApplyError::LogCorrupt);
                                        }
                                        self.sidecar.forkchoice_updated(latest_valid_hash)?;
                                        self.settled = Some(SettledHeight {
                                            height: value.height.0,
                                            pse_root: value.state_root,
                                            evm_root: latest_valid_hash,
                                            settlement_commitment: value.settlement_commitment,
                                        });
                                    }
                                    _ => return Err(ApplyError::LogCorrupt),
                                }
                                i += 2;
                                continue;
                            }
                        }
                    }
                    // dangling intent: stop; do not apply
                    break;
                }
                Rec::Commit { .. } => return Err(ApplyError::LogCorrupt),
            }
        }
        Ok(())
    }
}

enum Rec {
    Intent {
        value: ConsensusValue,
        deltas: Vec<SettlementDelta>,
    },
    Commit {
        height: Height,
        evm_root: Bytes32,
    },
}

fn open_log(path: &Path) -> io::Result<File> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
}

fn ensure_magic(path: &Path) -> io::Result<()> {
    let meta = std::fs::metadata(path);
    if meta.ok().map(|m| m.len() == 0).unwrap_or(true) {
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        f.write_all(MAGIC)?;
    }
    Ok(())
}

fn append_intent(
    path: &Path,
    value: &ConsensusValue,
    deltas: &[SettlementDelta],
) -> Result<(), ApplyError> {
    ensure_magic(path)?;
    let mut buf = EncodeBuf::new();
    buf.tag(*b"SETINTNT");
    value.encode(&mut buf);
    buf.u32(deltas.len() as u32);
    for d in deltas {
        d.encode(&mut buf);
    }
    let bytes = buf.into_vec();
    let mut f = open_log(path)?;
    f.write_all(&(bytes.len() as u32).to_le_bytes())?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    Ok(())
}

fn append_commit(path: &Path, height: Height, evm_root: Bytes32) -> Result<(), ApplyError> {
    ensure_magic(path)?;
    let mut buf = EncodeBuf::new();
    buf.tag(*b"SETCOMIT");
    height.encode(&mut buf);
    evm_root.encode(&mut buf);
    let bytes = buf.into_vec();
    let mut f = open_log(path)?;
    f.write_all(&(bytes.len() as u32).to_le_bytes())?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    Ok(())
}

fn read_all(path: &Path) -> Result<Vec<Rec>, ApplyError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut f = File::open(path)?;
    let mut all = Vec::new();
    f.read_to_end(&mut all)?;
    if all.is_empty() {
        return Ok(Vec::new());
    }
    if all.len() < 8 || &all[..8] != MAGIC {
        return Err(ApplyError::LogCorrupt);
    }
    let mut rest = &all[8..];
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(ApplyError::LogCorrupt);
        }
        let n = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        rest = &rest[4..];
        if rest.len() < n {
            return Err(ApplyError::LogCorrupt);
        }
        let rec = &rest[..n];
        rest = &rest[n..];
        out.push(decode_rec(rec)?);
    }
    Ok(out)
}

fn decode_rec(bytes: &[u8]) -> Result<Rec, ApplyError> {
    let mut buf = DecodeBuf::new(bytes);
    let tag = buf.bytes_fixed::<8>().map_err(|_| ApplyError::LogCorrupt)?;
    match &tag {
        b"SETINTNT" => {
            let value = ConsensusValue::decode(&mut buf).map_err(|_| ApplyError::LogCorrupt)?;
            let n = buf.u32().map_err(|_| ApplyError::LogCorrupt)? as usize;
            let mut deltas = Vec::with_capacity(n);
            for _ in 0..n {
                deltas.push(SettlementDelta::decode(&mut buf).map_err(|_| ApplyError::LogCorrupt)?);
            }
            if !buf.is_empty() {
                return Err(ApplyError::LogCorrupt);
            }
            Ok(Rec::Intent { value, deltas })
        }
        b"SETCOMIT" => {
            let height = Height::decode(&mut buf).map_err(|_| ApplyError::LogCorrupt)?;
            let evm_root = Bytes32::decode(&mut buf).map_err(|_| ApplyError::LogCorrupt)?;
            if !buf.is_empty() {
                return Err(ApplyError::LogCorrupt);
            }
            Ok(Rec::Commit { height, evm_root })
        }
        _ => Err(ApplyError::LogCorrupt),
    }
}

fn read_dangling_intent(
    path: &Path,
) -> Result<Option<(ConsensusValue, Vec<SettlementDelta>)>, ApplyError> {
    let recs = read_all(path)?;
    match recs.last() {
        Some(Rec::Intent { value, deltas }) => Ok(Some((value.clone(), deltas.clone()))),
        _ => Ok(None),
    }
}
