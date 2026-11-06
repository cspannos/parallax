//! Engine snapshot and the `F` statement for a zkVM guest (ADR 0025).
//!
//! [`run_f`] rebuilds an [`Engine`] from a canonical [`EngineSnapshot`],
//! computes its `C'` (`pre_root`), applies `I` with the real matcher, and
//! returns the `HeightStatement` fields `F` determines: `pre_root`,
//! `post_root`, `input_commitment`, `settlement_commitment`.
//!
//! Soundness rests on the snapshot → root map being injective: every engine
//! field the matcher reads is committed by the INC root, and
//! [`Engine::from_snapshot`] rejects any non-canonical snapshot (duplicate or
//! unsorted keys, duplicate rest times, unknown instruments), since the treap
//! would silently merge duplicates. Book FIFO order is rebuilt from `time`,
//! which the engine assigns uniquely and in arrival order.

use commitments::{commit_list_payload, Digest, TreapHash, INPUT_DOMAIN, RECEIPT_DOMAIN};
use protocol_types::{
    CanonicalDecode, CanonicalEncode, DecodeBuf, DecodeError, EncodeBuf, Height, Input,
    Instrument, InstrumentId, OrderId, OwnerId, Price, Qty, Side, TimeSeq,
};

use crate::book::RestingOrder;
use crate::btree_book::BTreeBook;
use crate::engine::{Engine, OrderIdRule};

/// Everything [`Engine`] needs to match, in canonical order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineSnapshot {
    pub hash: TreapHash,
    pub id_rule: OrderIdRule,
    pub height: Height,
    pub next_time: TimeSeq,
    /// Strictly increasing by id.
    pub instruments: Vec<Instrument>,
    /// Strictly increasing by owner.
    pub nonces: Vec<(OwnerId, u64)>,
    /// Strictly increasing.
    pub seen: Vec<OrderId>,
    /// Strictly increasing by `time` (book FIFO order).
    pub resting: Vec<RestingOrder>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    Decode(DecodeError),
    /// Keys not strictly increasing, or duplicate.
    NotCanonical,
    UnknownInstrument,
    /// Only `Sha256` (production) and `Blake3` (`C'` v1) are commitments.
    HashMode,
    /// Derived ids keep the seen set empty (ADR 0026).
    SeenUnderDerivedIds,
}

impl From<DecodeError> for SnapshotError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

fn strictly_increasing<T: Ord>(items: impl Iterator<Item = T>) -> bool {
    let mut prev: Option<T> = None;
    for x in items {
        if prev.as_ref().is_some_and(|p| *p >= x) {
            return false;
        }
        prev = Some(x);
    }
    true
}

impl EngineSnapshot {
    pub fn validate(&self) -> Result<(), SnapshotError> {
        self.validated_id_order().map(|_| ())
    }

    /// [`Self::validate`], returning `resting` indices in strictly increasing
    /// id order (the resting map's key order), so the rebuild sorts once.
    pub(crate) fn validated_id_order(&self) -> Result<Vec<u32>, SnapshotError> {
        if !matches!(self.hash, TreapHash::Sha256 | TreapHash::Blake3) {
            return Err(SnapshotError::HashMode);
        }
        if self.id_rule == OrderIdRule::DerivedFromOwnerNonce && !self.seen.is_empty() {
            return Err(SnapshotError::SeenUnderDerivedIds);
        }
        let canonical = strictly_increasing(self.instruments.iter().map(|i| i.id))
            && strictly_increasing(self.nonces.iter().map(|(o, _)| *o))
            && strictly_increasing(self.seen.iter().copied())
            && strictly_increasing(self.resting.iter().map(|r| r.time));
        let mut by_id: Vec<u32> = (0..self.resting.len() as u32).collect();
        by_id.sort_unstable_by_key(|&i| self.resting[i as usize].id);
        let ids_unique = strictly_increasing(by_id.iter().map(|&i| self.resting[i as usize].id));
        if !canonical || !ids_unique {
            return Err(SnapshotError::NotCanonical);
        }
        let known = |id: InstrumentId| self.instruments.iter().any(|i| i.id == id);
        if !self.resting.iter().all(|r| known(r.instrument)) {
            return Err(SnapshotError::UnknownInstrument);
        }
        Ok(by_id)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = EncodeBuf::new();
        b.u8(flags(self.hash, self.id_rule));
        self.height.encode(&mut b);
        self.next_time.encode(&mut b);
        b.u32(self.instruments.len() as u32);
        for i in &self.instruments {
            i.encode(&mut b);
        }
        b.u32(self.nonces.len() as u32);
        for (o, n) in &self.nonces {
            o.encode(&mut b);
            b.u64(*n);
        }
        b.u32(self.seen.len() as u32);
        for id in &self.seen {
            id.encode(&mut b);
        }
        b.u32(self.resting.len() as u32);
        for r in &self.resting {
            r.encode_leaf(&mut b);
        }
        b.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SnapshotError> {
        let mut b = DecodeBuf::new(bytes);
        let (hash, id_rule) = unflags(b.u8()?).ok_or(SnapshotError::HashMode)?;
        let height = Height::decode(&mut b)?;
        let next_time = TimeSeq::decode(&mut b)?;
        let n = b.u32()? as usize;
        let instruments = (0..n).map(|_| Instrument::decode(&mut b)).collect::<Result<_, _>>()?;
        // Pre-size from the count, capped by the bytes left (untrusted input).
        let n = b.u32()? as usize;
        let mut nonces = Vec::with_capacity(n.min(b.remaining() / 40));
        for _ in 0..n {
            nonces.push((OwnerId::decode(&mut b)?, b.u64()?));
        }
        let n = b.u32()? as usize;
        let mut seen = Vec::with_capacity(n.min(b.remaining() / 16));
        for _ in 0..n {
            seen.push(OrderId::decode(&mut b)?);
        }
        let n = b.u32()? as usize;
        let mut resting = Vec::with_capacity(n.min(b.remaining() / RESTING_LEAF_BYTES));
        for _ in 0..n {
            resting.push(decode_leaf(&mut b)?);
        }
        if !b.is_empty() {
            return Err(SnapshotError::Decode(DecodeError::TrailingBytes));
        }
        Ok(Self { hash, id_rule, height, next_time, instruments, nonces, seen, resting })
    }
}

/// Flag byte: bit 0 = SHA-256 `C'` (ADR 0024), bit 1 = derived ids (ADR 0026).
/// Production is `0b11`.
pub const F_FLAGS_PRODUCTION: u8 = 0b11;

fn flags(hash: TreapHash, id_rule: OrderIdRule) -> u8 {
    u8::from(hash == TreapHash::Sha256) | (u8::from(id_rule == OrderIdRule::DerivedFromOwnerNonce) << 1)
}

fn unflags(f: u8) -> Option<(TreapHash, OrderIdRule)> {
    if f > 0b11 {
        return None;
    }
    let hash = if f & 1 == 1 { TreapHash::Sha256 } else { TreapHash::Blake3 };
    let rule = if f & 2 == 2 {
        OrderIdRule::DerivedFromOwnerNonce
    } else {
        OrderIdRule::ClientChosen
    };
    Some((hash, rule))
}

/// Encoded size of one resting leaf (`RESTING` tag + fields).
const RESTING_LEAF_BYTES: usize = 8 + 16 + 4 + 1 + 8 + 8 + 32 + 8 + 8 + 8;

/// Inverse of [`RestingOrder::encode_leaf`].
fn decode_leaf(b: &mut DecodeBuf<'_>) -> Result<RestingOrder, DecodeError> {
    b.expect_tag(*b"RESTING\0")?;
    Ok(RestingOrder {
        id: OrderId::decode(b)?,
        instrument: InstrumentId::decode(b)?,
        side: Side::decode(b)?,
        remaining: Qty::decode(b)?,
        price: Price::decode(b)?,
        owner: OwnerId::decode(b)?,
        expiry: Height::decode(b)?,
        nonce: b.u64()?,
        time: TimeSeq::decode(b)?,
    })
}

/// The `HeightStatement` fields `F` determines (not `parent` / `height`,
/// which are consensus metadata).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FClaim {
    pub hash: TreapHash,
    pub id_rule: OrderIdRule,
    pub pre_root: Digest,
    pub post_root: Digest,
    pub input_commitment: Digest,
    pub settlement_commitment: Digest,
}

/// Journal length of [`FClaim::to_bytes`].
pub const F_CLAIM_BYTES: usize = 1 + 32 * 4;

impl FClaim {
    pub fn to_bytes(&self) -> [u8; F_CLAIM_BYTES] {
        let mut out = [0u8; F_CLAIM_BYTES];
        out[0] = flags(self.hash, self.id_rule);
        out[1..33].copy_from_slice(&self.pre_root.0);
        out[33..65].copy_from_slice(&self.post_root.0);
        out[65..97].copy_from_slice(&self.input_commitment.0);
        out[97..129].copy_from_slice(&self.settlement_commitment.0);
        out
    }

    /// Does this claim prove `stmt` (ignoring consensus `parent` / `height`)?
    pub fn matches(&self, stmt: &protocol_types::HeightStatement) -> bool {
        self.pre_root.0 == stmt.pre_root.0
            && self.post_root.0 == stmt.post_root.0
            && self.input_commitment.0 == stmt.input_commitment.0
            && self.settlement_commitment.0 == stmt.settlement_commitment.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FError {
    Snapshot(SnapshotError),
    Inputs(DecodeError),
}

/// Decode `u32 count ‖ Input*` (the [`commit_list_payload`] of `I`).
pub fn decode_inputs(bytes: &[u8]) -> Result<Vec<Input>, DecodeError> {
    let mut b = DecodeBuf::new(bytes);
    let n = b.u32()? as usize;
    let inputs = (0..n).map(|_| Input::decode(&mut b)).collect::<Result<Vec<_>, _>>()?;
    if !b.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(inputs)
}

/// `F` from bytes: rebuild, commit `C`, apply `I`, commit `C'` / `I` / deltas.
pub fn run_f(snapshot: &[u8], inputs: &[u8]) -> Result<FClaim, FError> {
    let snap = EngineSnapshot::decode(snapshot).map_err(FError::Snapshot)?;
    let inputs = decode_inputs(inputs).map_err(FError::Inputs)?;
    let mut e = Engine::<BTreeBook>::from_snapshot(&snap).map_err(FError::Snapshot)?;
    // Per-receipt roots are not part of the statement; deltas do not depend on them.
    e.commit_on_apply = false;
    let pre_root = e.state_root();
    let receipts = e.apply_all(inputs.iter().cloned());
    let settlement: Vec<_> = receipts.into_iter().flat_map(|r| r.settlement).collect();
    Ok(FClaim {
        hash: snap.hash,
        id_rule: snap.id_rule,
        pre_root,
        post_root: e.state_root(),
        input_commitment: Digest::from_bytes(&commit_list_payload(&inputs), INPUT_DOMAIN),
        settlement_commitment: Digest::from_bytes(&commit_list_payload(&settlement), RECEIPT_DOMAIN),
    })
}

/// One `π` of `F` job (ADR 0028): what a FULL_VIEW follower hands an external
/// prover for a decided height. `statement` is the public instance; `snapshot`
/// and `inputs` are the private witness (`run_f`'s arguments).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FJob {
    pub statement: protocol_types::HeightStatement,
    pub snapshot: Vec<u8>,
    /// `commit_list_payload(I)`.
    pub inputs: Vec<u8>,
}

const FJOB_MAGIC: &[u8; 8] = b"PLXFJOB1";

impl FJob {
    pub fn encode(&self) -> Vec<u8> {
        let stmt = self.statement.encode_vec();
        let mut out = Vec::with_capacity(8 + 12 + stmt.len() + self.snapshot.len() + self.inputs.len());
        out.extend_from_slice(FJOB_MAGIC);
        for part in [&stmt[..], &self.snapshot[..], &self.inputs[..]] {
            out.extend_from_slice(&(part.len() as u32).to_le_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(FJOB_MAGIC)?;
        let mut parts = Vec::with_capacity(3);
        let mut at = 0usize;
        for _ in 0..3 {
            let n = u32::from_le_bytes(rest.get(at..at + 4)?.try_into().ok()?) as usize;
            parts.push(rest.get(at + 4..at + 4 + n)?.to_vec());
            at += 4 + n;
        }
        if at != rest.len() {
            return None;
        }
        let inputs = parts.pop()?;
        let snapshot = parts.pop()?;
        let statement = protocol_types::HeightStatement::decode_slice(&parts.pop()?).ok()?;
        Some(Self { statement, snapshot, inputs })
    }

    /// The `f_guest` input: `u32 snapshot_len ‖ snapshot ‖ inputs`.
    pub fn guest_input(&self) -> Vec<u8> {
        let mut out = (self.snapshot.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(&self.snapshot);
        out.extend_from_slice(&self.inputs);
        out
    }

    /// Does a guest journal prove this job's statement under production rules?
    pub fn journal_matches(&self, journal: &[u8]) -> bool {
        journal.len() == F_CLAIM_BYTES
            && journal[0] == F_FLAGS_PRODUCTION
            && journal[1..33] == self.statement.pre_root.0
            && journal[33..65] == self.statement.post_root.0
            && journal[65..97] == self.statement.input_commitment.0
            && journal[97..129] == self.statement.settlement_commitment.0
    }
}

