//! WAL-then-apply replica.

use std::path::{Path, PathBuf};

use clob::{BTreeBook, Engine, Genesis, Receipt};
use commitments::StateRoot;
use protocol_types::{
    CanonicalDecode, CanonicalEncode, DecodeBuf, DecodeError, EncodeBuf, GenesisBlob, Input,
};
use storage::{EncryptedWal, SyncMode, WalError};

#[derive(Debug)]
pub enum ReplicaError {
    Wal(WalError),
    Decode(protocol_types::DecodeError),
    SimulatedCrash,
}

impl From<WalError> for ReplicaError {
    fn from(e: WalError) -> Self {
        Self::Wal(e)
    }
}

impl std::fmt::Display for ReplicaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wal(e) => write!(f, "{e}"),
            Self::Decode(e) => write!(f, "input decode: {e}"),
            Self::SimulatedCrash => write!(f, "simulated crash after wal"),
        }
    }
}

impl std::error::Error for ReplicaError {}

#[derive(Clone, Debug)]
pub struct ReplicaOpts {
    pub wal_path: PathBuf,
    pub key: [u8; 32],
    pub genesis: Genesis,
    pub sync: SyncMode,
}

impl ReplicaOpts {
    pub fn new(wal_path: impl AsRef<Path>, key: [u8; 32], genesis: Genesis) -> Self {
        Self {
            wal_path: wal_path.as_ref().to_path_buf(),
            key,
            genesis,
            sync: SyncMode::Full,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenInfo {
    pub replayed: u64,
    pub wal_records: u64,
    pub truncated_tail: bool,
}

const TAPE_TAG: [u8; 8] = *b"PLXTAPE\0";

fn encode_wal_payload(inputs: &[Input]) -> Vec<u8> {
    let mut buf = EncodeBuf::new();
    buf.tag(TAPE_TAG);
    buf.u32(inputs.len() as u32);
    for input in inputs {
        input.encode(&mut buf);
    }
    buf.into_vec()
}

fn decode_wal_payload(raw: &[u8]) -> Result<Vec<Input>, DecodeError> {
    if raw.len() >= 8 && raw[..8] == TAPE_TAG {
        let mut buf = DecodeBuf::new(&raw[8..]);
        let n = buf.u32()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(Input::decode(&mut buf)?);
        }
        if !buf.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(out)
    } else {
        Ok(vec![Input::decode_slice(raw)?])
    }
}

#[cfg(test)]
mod payload_tests {
    use super::*;
    use clob::testutil::{limit, oid, owner};
    use protocol_types::Side;

    #[test]
    fn tape_roundtrip_and_legacy_input() {
        let inputs = vec![
            Input::Place(limit(1, 1, Side::Buy, 1, 10, 1)),
            Input::Cancel {
                order_id: oid(1),
                owner: owner(1),
                nonce: 2,
            },
        ];
        let raw = encode_wal_payload(&inputs);
        assert_eq!(&raw[..8], &TAPE_TAG);
        assert_eq!(decode_wal_payload(&raw).unwrap(), inputs);
        let one = inputs[0].encode_vec();
        assert_eq!(decode_wal_payload(&one).unwrap(), vec![inputs[0].clone()]);
    }
}

pub struct Replica {
    engine: Engine<BTreeBook>,
    wal: EncryptedWal,
    /// Test hook: return after a successful WAL write, before `apply`.
    pub crash_after_wal: bool,
}

impl Replica {
    pub fn open(opts: ReplicaOpts) -> Result<(Self, OpenInfo), ReplicaError> {
        let blob = GenesisBlob {
            height: opts.genesis.height,
            instruments: opts.genesis.instruments.clone(),
        };
        let (wal, replay) =
            EncryptedWal::open_or_create(&opts.wal_path, opts.key, blob, opts.sync)?;
        let genesis = Genesis {
            height: replay.genesis.height,
            instruments: replay.genesis.instruments.clone(),
        };
        let mut engine = Engine::<BTreeBook>::new(genesis);
        let mut replayed = 0u64;
        for raw in &replay.records {
            let inputs = decode_wal_payload(raw).map_err(ReplicaError::Decode)?;
            replayed += inputs.len() as u64;
            for input in inputs {
                engine.apply(input);
            }
        }
        Ok((
            Self {
                engine,
                wal,
                crash_after_wal: false,
            },
            OpenInfo {
                replayed,
                wal_records: replay.records.len() as u64,
                truncated_tail: replay.truncated_tail,
            },
        ))
    }

    pub fn submit(&mut self, input: Input) -> Result<Receipt, ReplicaError> {
        self.wal.append(&input.encode_vec())?;
        if self.crash_after_wal {
            return Err(ReplicaError::SimulatedCrash);
        }
        Ok(self.engine.apply(input))
    }

    /// Encode the tape as one `PLXTAPE` record (ADR 0014). Height then
    /// `sync_all`. `Full` `submit_batch` stays per-input.
    pub fn submit_batch(
        &mut self,
        inputs: impl IntoIterator<Item = Input>,
    ) -> Result<Vec<Receipt>, ReplicaError> {
        let inputs: Vec<Input> = inputs.into_iter().collect();
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        if self.wal.sync_mode() == SyncMode::Full {
            let mut receipts = Vec::with_capacity(inputs.len());
            for input in inputs {
                receipts.push(self.submit(input)?);
            }
            return Ok(receipts);
        }
        self.persist_batch(inputs.iter().cloned())?;
        if self.crash_after_wal {
            return Err(ReplicaError::SimulatedCrash);
        }
        // Height batches are checked by their final root only, so skip the
        // per-receipt roots (each would flush the lazy treap, ADR 0032).
        let per_receipt = std::mem::replace(&mut self.engine.commit_on_apply, false);
        let receipts = self.engine.apply_all(inputs);
        self.engine.commit_on_apply = per_receipt;
        Ok(receipts)
    }

    pub fn persist_batch(
        &mut self,
        inputs: impl IntoIterator<Item = Input>,
    ) -> Result<(), ReplicaError> {
        let inputs: Vec<Input> = inputs.into_iter().collect();
        if inputs.is_empty() {
            return Ok(());
        }
        self.wal.append(&encode_wal_payload(&inputs))?;
        if self.wal.sync_mode() == SyncMode::Height {
            self.wal.sync_all()?;
        }
        Ok(())
    }

    /// Replace the in-memory engine. Caller already WAL'd `I` that produced it.
    pub fn install_engine(&mut self, engine: Engine<BTreeBook>) {
        self.engine = engine;
    }

    pub fn state_root(&self) -> StateRoot {
        self.engine.state_root()
    }

    pub fn engine(&self) -> &Engine<BTreeBook> {
        &self.engine
    }

    pub fn engine_mut(&mut self) -> &mut Engine<BTreeBook> {
        &mut self.engine
    }

    pub fn set_sync(&mut self, sync: SyncMode) {
        self.wal.set_sync(sync);
    }

    pub fn durability_sync(&mut self) -> Result<(), ReplicaError> {
        self.wal.sync_all()?;
        Ok(())
    }
}
