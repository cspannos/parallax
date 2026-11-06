//! File-backed XChaCha20-Poly1305 WAL.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use protocol_types::{CanonicalDecode, CanonicalEncode, DecodeError, GenesisBlob};

pub const MAGIC: [u8; 8] = *b"PLXWAL01";
pub const WAL_VERSION: u16 = 1;
const HEADER_PREFIX_LEN: usize = 8 + 2 + 4; // magic + version + genesis_len
const RECORD_PREFIX_LEN: usize = 8 + 24 + 4; // seq + nonce + ct_len
const MAX_CIPHERTEXT: u32 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncMode {
    /// `sync_all` after header writes and every record. Default for M2 tests.
    Full,
    /// Flush the process buffer only. Benches / explicit opt-in.
    Relaxed,
    /// Flush each record; caller `sync_all`s once per height (ADR 0012).
    /// Crash mid-tape can lose records that were not decided.
    Height,
}

#[derive(Debug)]
pub enum WalError {
    Io(io::Error),
    Corrupt(&'static str),
    Decrypt,
    Decode(DecodeError),
    GenesisMismatch,
    RecordTooLarge,
    BadKey,
}

impl From<io::Error> for WalError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<DecodeError> for WalError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "wal io: {e}"),
            Self::Corrupt(msg) => write!(f, "wal corrupt: {msg}"),
            Self::Decrypt => write!(f, "wal decrypt/auth failed"),
            Self::Decode(e) => write!(f, "wal decode: {e}"),
            Self::GenesisMismatch => write!(f, "wal genesis does not match replica config"),
            Self::RecordTooLarge => write!(f, "wal record exceeds cap"),
            Self::BadKey => write!(f, "wal key must be 32 bytes"),
        }
    }
}

impl std::error::Error for WalError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    pub genesis: GenesisBlob,
    pub records: Vec<Vec<u8>>,
    /// Last record was incomplete. Never accepted; discarded on open.
    pub truncated_tail: bool,
}

pub struct EncryptedWal {
    file: File,
    key: [u8; 32],
    next_seq: u64,
    sync: SyncMode,
    genesis: GenesisBlob,
}

impl EncryptedWal {
    pub fn open_or_create(
        path: impl AsRef<Path>,
        key: [u8; 32],
        genesis: GenesisBlob,
        sync: SyncMode,
    ) -> Result<(Self, Replay), WalError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        let meta = file.metadata()?;
        if meta.len() == 0 {
            write_header(&mut file, &genesis, sync)?;
            return Ok((
                Self {
                    file,
                    key,
                    next_seq: 0,
                    sync,
                    genesis: genesis.clone(),
                },
                Replay {
                    genesis,
                    records: Vec::new(),
                    truncated_tail: false,
                },
            ));
        }

        let stored = read_header(&mut file)?;
        if stored != genesis {
            return Err(WalError::GenesisMismatch);
        }

        let mut records = Vec::new();
        let mut next_seq = 0u64;
        let mut truncated_tail = false;
        let mut complete_end = file.stream_position()?;

        loop {
            match read_record(&mut file, &key, next_seq)? {
                RecordRead::Eof => break,
                RecordRead::Truncated => {
                    truncated_tail = true;
                    break;
                }
                RecordRead::Complete {
                    seq,
                    plaintext,
                    consumed,
                } => {
                    debug_assert_eq!(seq, next_seq);
                    records.push(plaintext);
                    next_seq = seq + 1;
                    complete_end += consumed;
                }
            }
        }

        if truncated_tail {
            file.set_len(complete_end)?;
            if sync == SyncMode::Full {
                file.sync_all()?;
            }
        }
        file.seek(SeekFrom::Start(complete_end))?;

        Ok((
            Self {
                file,
                key,
                next_seq,
                sync,
                genesis: stored.clone(),
            },
            Replay {
                genesis: stored,
                records,
                truncated_tail,
            },
        ))
    }

    pub fn genesis(&self) -> &GenesisBlob {
        &self.genesis
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Encrypt and append. The record is durable (under `SyncMode::Full`)
    /// before this returns. Caller then applies `F`.
    pub fn append(&mut self, plaintext: &[u8]) -> Result<u64, WalError> {
        let seq = self.next_seq;
        let nonce = nonce_for_seq(seq);
        let aad = aad_for_seq(seq);
        let cipher = cipher(&self.key)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| WalError::Decrypt)?;
        if ciphertext.len() > MAX_CIPHERTEXT as usize {
            return Err(WalError::RecordTooLarge);
        }

        let ct_len = ciphertext.len() as u32;
        self.file.write_all(&seq.to_le_bytes())?;
        self.file.write_all(&nonce)?;
        self.file.write_all(&ct_len.to_le_bytes())?;
        self.file.write_all(&ciphertext)?;
        persist(&mut self.file, self.sync)?;
        self.next_seq += 1;
        Ok(seq)
    }

    pub fn sync_mode(&self) -> SyncMode {
        self.sync
    }

    pub fn set_sync(&mut self, sync: SyncMode) {
        self.sync = sync;
    }

    /// Process-wide durability. Used for height-batch WAL (Q-STO-3 experiment).
    /// Does not change [`SyncMode`]. Crash before this call can lose Relaxed records.
    pub fn sync_all(&mut self) -> Result<(), WalError> {
        self.file.sync_all()?;
        Ok(())
    }
}

fn cipher(key: &[u8; 32]) -> Result<XChaCha20Poly1305, WalError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| WalError::BadKey)
}

fn nonce_for_seq(seq: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..8].copy_from_slice(&seq.to_le_bytes());
    n
}

fn aad_for_seq(seq: u64) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(&MAGIC);
    aad[8..].copy_from_slice(&seq.to_le_bytes());
    aad
}

fn write_header(file: &mut File, genesis: &GenesisBlob, sync: SyncMode) -> Result<(), WalError> {
    let blob = genesis.encode_vec();
    file.write_all(&MAGIC)?;
    file.write_all(&WAL_VERSION.to_le_bytes())?;
    file.write_all(&(blob.len() as u32).to_le_bytes())?;
    file.write_all(&blob)?;
    persist(file, sync)?;
    Ok(())
}

fn persist(file: &mut File, sync: SyncMode) -> io::Result<()> {
    match sync {
        SyncMode::Full => file.sync_all(),
        SyncMode::Relaxed | SyncMode::Height => file.flush(),
    }
}

fn read_header(file: &mut File) -> Result<GenesisBlob, WalError> {
    let mut prefix = [0u8; HEADER_PREFIX_LEN];
    read_exact(file, &mut prefix).map_err(|e| match e {
        ReadFill::Eof | ReadFill::Partial => WalError::Corrupt("truncated header"),
        ReadFill::Io(err) => WalError::Io(err),
    })?;
    if prefix[..8] != MAGIC {
        return Err(WalError::Corrupt("bad magic"));
    }
    let version = u16::from_le_bytes([prefix[8], prefix[9]]);
    if version != WAL_VERSION {
        return Err(WalError::Corrupt("unsupported version"));
    }
    let mut glen_bytes = [0u8; 4];
    glen_bytes.copy_from_slice(&prefix[10..14]);
    let glen = u32::from_le_bytes(glen_bytes) as usize;
    if glen > MAX_CIPHERTEXT as usize {
        return Err(WalError::RecordTooLarge);
    }
    let mut blob = vec![0u8; glen];
    read_exact(file, &mut blob).map_err(|e| match e {
        ReadFill::Eof | ReadFill::Partial => WalError::Corrupt("truncated genesis"),
        ReadFill::Io(err) => WalError::Io(err),
    })?;
    Ok(GenesisBlob::decode_slice(&blob)?)
}

enum RecordRead {
    Complete {
        seq: u64,
        plaintext: Vec<u8>,
        consumed: u64,
    },
    Truncated,
    Eof,
}

fn read_record(file: &mut File, key: &[u8; 32], expected_seq: u64) -> Result<RecordRead, WalError> {
    let mut prefix = [0u8; RECORD_PREFIX_LEN];
    match read_exact(file, &mut prefix) {
        Ok(()) => {}
        Err(ReadFill::Eof) => return Ok(RecordRead::Eof),
        Err(ReadFill::Partial) => return Ok(RecordRead::Truncated),
        Err(ReadFill::Io(e)) => return Err(WalError::Io(e)),
    }

    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&prefix[0..8]);
    let seq = u64::from_le_bytes(seq_bytes);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&prefix[8..32]);
    let mut ct_len_bytes = [0u8; 4];
    ct_len_bytes.copy_from_slice(&prefix[32..36]);
    let ct_len = u32::from_le_bytes(ct_len_bytes);
    if ct_len > MAX_CIPHERTEXT {
        return Err(WalError::RecordTooLarge);
    }
    if seq != expected_seq {
        return Err(WalError::Corrupt("sequence gap"));
    }

    let mut ciphertext = vec![0u8; ct_len as usize];
    match read_exact(file, &mut ciphertext) {
        Ok(()) => {}
        Err(ReadFill::Eof) | Err(ReadFill::Partial) => return Ok(RecordRead::Truncated),
        Err(ReadFill::Io(e)) => return Err(WalError::Io(e)),
    }

    let aad = aad_for_seq(seq);
    let cipher = cipher(key)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| WalError::Decrypt)?;

    Ok(RecordRead::Complete {
        seq,
        plaintext,
        consumed: (RECORD_PREFIX_LEN as u32 + ct_len) as u64,
    })
}

enum ReadFill {
    Eof,
    Partial,
    Io(io::Error),
}

fn read_exact(file: &mut File, buf: &mut [u8]) -> Result<(), ReadFill> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Err(ReadFill::Eof),
            Ok(0) => return Err(ReadFill::Partial),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadFill::Io(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{AssetId, Height, Instrument, InstrumentId, Price, Qty};

    fn genesis() -> GenesisBlob {
        GenesisBlob {
            height: Height(1),
            instruments: vec![Instrument {
                id: InstrumentId(1),
                base: AssetId(1),
                quote: AssetId(2),
                lot_size: Qty(1),
                tick_size: Price(1),
            }],
        }
    }

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn height_append_then_sync_all_replays() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal");
        {
            let (mut wal, _) =
                EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Height).unwrap();
            wal.append(b"a").unwrap();
            wal.append(b"b").unwrap();
            wal.sync_all().unwrap();
        }
        let (_wal, replay) =
            EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Height).unwrap();
        assert_eq!(replay.records, [b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn relaxed_then_sync_all_replays() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal");
        {
            let (mut wal, _) =
                EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Relaxed).unwrap();
            wal.append(b"a").unwrap();
            wal.append(b"b").unwrap();
            wal.sync_all().unwrap();
        }
        let (_wal, replay) =
            EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Relaxed).unwrap();
        assert_eq!(replay.records, [b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn append_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal");
        {
            let (mut wal, replay) =
                EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Full).unwrap();
            assert!(replay.records.is_empty());
            wal.append(b"one").unwrap();
            wal.append(b"two").unwrap();
        }
        let (_wal, replay) =
            EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Full).unwrap();
        assert_eq!(replay.records, [b"one".to_vec(), b"two".to_vec()]);
        assert!(!replay.truncated_tail);
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal");
        {
            let (mut wal, _) =
                EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Full).unwrap();
            wal.append(b"secret").unwrap();
        }
        let err = EncryptedWal::open_or_create(&path, key(2), genesis(), SyncMode::Full)
            .err()
            .unwrap();
        assert!(matches!(err, WalError::Decrypt));
    }

    #[test]
    fn truncated_tail_detected_and_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal");
        {
            let (mut wal, _) =
                EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Full).unwrap();
            wal.append(b"keep").unwrap();
            wal.append(b"drop-me").unwrap();
        }
        let meta = std::fs::metadata(&path).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(meta.len() - 3)
            .unwrap();

        let (_wal, replay) =
            EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Full).unwrap();
        assert!(replay.truncated_tail);
        assert_eq!(replay.records, [b"keep".to_vec()]);
    }

    #[test]
    fn corrupt_byte_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal");
        {
            let (mut wal, _) =
                EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Full).unwrap();
            wal.append(b"alpha").unwrap();
            wal.append(b"beta").unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 8;
        bytes[last] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();

        let err = EncryptedWal::open_or_create(&path, key(1), genesis(), SyncMode::Full)
            .err()
            .unwrap();
        assert!(matches!(err, WalError::Decrypt | WalError::Corrupt(_)));
    }
}
