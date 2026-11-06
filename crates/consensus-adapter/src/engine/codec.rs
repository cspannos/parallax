//! Canonical-LE codec for Parallax consensus messages (not protobuf, not JSON).

use bytes::Bytes;
use malachitebft_codec::{Codec, HasEncodedLen};
use malachitebft_core_consensus::{LivenessMsg, ProposedValue, SignedConsensusMsg};
use malachitebft_core_types::{
    CommitCertificate, CommitSignature, ExtendedCommitCertificate, ExtendedCommitSignature,
    NilOrVal, PolkaCertificate, PolkaSignature, Round, RoundCertificate, RoundCertificateType,
    RoundSignature, SignedExtension, SignedProposal, SignedVote, ValidatorProof, Validity,
    VoteType,
};
use malachitebft_engine::util::streaming::{StreamContent, StreamId, StreamMessage};
use crypto_suite::SuiteSignature as Signature;
use malachitebft_sync::{self as sync, PeerId, RawDecidedValue, Request, Response, Status};
use protocol_types::{CanonicalDecode, CanonicalEncode, ConsensusValue};

use super::context::{
    Address, ConsHeight, PlxContext, PlxValue, Proposal, ProposalPart, ValueId, Vote,
};

#[derive(Copy, Clone, Debug, Default)]
pub struct PlxCodec;

/// Consensus bytes received, counted at decode (decode runs on network
/// receipt; the WAL only decodes on replay). Process-wide: a bench runs one
/// cluster at a time and calls [`wire_reset`] first. Summed over nodes, this
/// is the bytes every node sent.
pub mod wire {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    pub(super) static SIGNED_MSGS: AtomicU64 = AtomicU64::new(0);
    pub(super) static SIGNED_BYTES: AtomicU64 = AtomicU64::new(0);
    pub(super) static OTHER_BYTES: AtomicU64 = AtomicU64::new(0);
    pub(super) static FINALITY_BYTES: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct WireStats {
        /// Votes, proposals and liveness messages (each carries signatures).
        pub signed_msgs: u64,
        pub signed_bytes: u64,
        /// Proposal parts (the value itself).
        pub other_bytes: u64,
        /// Finality signatures sent to collectors (ADR 0031).
        pub finality_bytes: u64,
    }

    pub fn wire_reset() {
        for c in [&SIGNED_MSGS, &SIGNED_BYTES, &OTHER_BYTES, &FINALITY_BYTES] {
            c.store(0, Relaxed);
        }
    }

    pub fn wire_stats() -> WireStats {
        WireStats {
            signed_msgs: SIGNED_MSGS.load(Relaxed),
            signed_bytes: SIGNED_BYTES.load(Relaxed),
            other_bytes: OTHER_BYTES.load(Relaxed),
            finality_bytes: FINALITY_BYTES.load(Relaxed),
        }
    }

    pub(super) fn signed(len: usize) {
        SIGNED_MSGS.fetch_add(1, Relaxed);
        SIGNED_BYTES.fetch_add(len as u64, Relaxed);
    }

    pub(in crate::engine) fn finality(len: usize) {
        FINALITY_BYTES.fetch_add(len as u64, Relaxed);
    }

    pub(super) fn other(len: usize) {
        OTHER_BYTES.fetch_add(len as u64, Relaxed);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("truncated")]
    Truncated,
    #[error("unknown tag {0}")]
    Tag(u8),
    #[error("decode: {0:?}")]
    Protocol(protocol_types::DecodeError),
    #[error("{0}")]
    Other(&'static str),
}

struct W(Vec<u8>);

impl W {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    fn finish(self) -> Bytes {
        Bytes::from(self.0)
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn u8(&mut self) -> Result<u8, CodecError> {
        let (h, t) = self.0.split_first().ok_or(CodecError::Truncated)?;
        self.0 = t;
        Ok(*h)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.0.len() < n {
            return Err(CodecError::Truncated);
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, CodecError> {
        let b = self.take(8)?;
        Ok(i64::from_le_bytes(b.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn arr20(&mut self) -> Result<[u8; 20], CodecError> {
        Ok(self.take(20)?.try_into().unwrap())
    }
    fn arr32(&mut self) -> Result<[u8; 32], CodecError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

fn round_enc(r: Round) -> i64 {
    r.as_i64()
}

fn round_dec(v: i64) -> Round {
    Round::from(v)
}

fn vote_type_enc(t: VoteType) -> u8 {
    match t {
        VoteType::Prevote => 1,
        VoteType::Precommit => 2,
    }
}

fn vote_type_dec(v: u8) -> Result<VoteType, CodecError> {
    match v {
        1 => Ok(VoteType::Prevote),
        2 => Ok(VoteType::Precommit),
        t => Err(CodecError::Tag(t)),
    }
}

/// Length-prefixed suite signature (70 B classical, 3 379 B hybrid).
fn signature_enc(w: &mut W, s: &Signature) {
    w.bytes(&s.encode());
}

fn signature_dec(r: &mut R<'_>) -> Result<Signature, CodecError> {
    Signature::decode(&r.bytes()?).ok_or(CodecError::Other("suite signature"))
}

fn address_enc(w: &mut W, a: &Address) {
    w.0.extend_from_slice(a.as_bytes());
}

fn address_dec(r: &mut R<'_>) -> Result<Address, CodecError> {
    Ok(Address::new(r.arr20()?))
}

fn height_enc(w: &mut W, h: ConsHeight) {
    w.u64(h.as_u64());
}

fn height_dec(r: &mut R<'_>) -> Result<ConsHeight, CodecError> {
    Ok(ConsHeight::new(r.u64()?))
}

fn value_id_enc(w: &mut W, id: &ValueId) {
    w.0.extend_from_slice(&id.0 .0);
}

fn value_id_dec(r: &mut R<'_>) -> Result<ValueId, CodecError> {
    Ok(ValueId(commitments::Digest(r.arr32()?)))
}

fn plx_value_enc(w: &mut W, v: &PlxValue) {
    let bytes = v.0.encode_vec();
    w.bytes(&bytes);
}

fn plx_value_dec(r: &mut R<'_>) -> Result<PlxValue, CodecError> {
    let bytes = r.bytes()?;
    let v = ConsensusValue::decode_slice(&bytes).map_err(CodecError::Protocol)?;
    Ok(PlxValue(v))
}

pub fn encode_vote(vote: &Vote) -> Vec<u8> {
    let mut w = W::new();
    w.u8(vote_type_enc(vote.typ));
    height_enc(&mut w, vote.height);
    w.i64(round_enc(vote.round));
    match &vote.value {
        NilOrVal::Nil => w.u8(0),
        NilOrVal::Val(id) => {
            w.u8(1);
            value_id_enc(&mut w, id);
        }
    }
    address_enc(&mut w, &vote.validator_address);
    match &vote.extension {
        None => w.u8(0),
        Some(ext) => {
            w.u8(1);
            w.bytes(&ext.message);
            signature_enc(&mut w, &ext.signature);
        }
    }
    w.0
}

fn decode_vote(r: &mut R<'_>) -> Result<Vote, CodecError> {
    let typ = vote_type_dec(r.u8()?)?;
    let height = height_dec(r)?;
    let round = round_dec(r.i64()?);
    let value = match r.u8()? {
        0 => NilOrVal::Nil,
        1 => NilOrVal::Val(value_id_dec(r)?),
        t => return Err(CodecError::Tag(t)),
    };
    let validator_address = address_dec(r)?;
    let extension = match r.u8()? {
        0 => None,
        1 => {
            let message = Bytes::from(r.bytes()?);
            let signature = signature_dec(r)?;
            Some(SignedExtension::<PlxContext>::new(message, signature))
        }
        t => return Err(CodecError::Tag(t)),
    };
    Ok(Vote {
        typ,
        height,
        round,
        value,
        validator_address,
        extension,
    })
}

pub fn encode_proposal(p: &Proposal) -> Vec<u8> {
    let mut w = W::new();
    height_enc(&mut w, p.height);
    w.i64(round_enc(p.round));
    plx_value_enc(&mut w, &p.value);
    w.i64(round_enc(p.pol_round));
    address_enc(&mut w, &p.validator_address);
    w.0
}

fn decode_proposal(r: &mut R<'_>) -> Result<Proposal, CodecError> {
    Ok(Proposal {
        height: height_dec(r)?,
        round: round_dec(r.i64()?),
        value: plx_value_dec(r)?,
        pol_round: round_dec(r.i64()?),
        validator_address: address_dec(r)?,
    })
}

fn encode_signed_vote(v: &SignedVote<PlxContext>) -> Bytes {
    let mut w = W::new();
    w.bytes(&encode_vote(&v.message));
    signature_enc(&mut w, &v.signature);
    w.finish()
}

fn decode_signed_vote(bytes: &[u8]) -> Result<SignedVote<PlxContext>, CodecError> {
    let mut r = R(bytes);
    let inner = r.bytes()?;
    let vote = decode_vote(&mut R(&inner))?;
    let signature = signature_dec(&mut r)?;
    Ok(SignedVote::new(vote, signature))
}

fn encode_signed_proposal(p: &SignedProposal<PlxContext>) -> Bytes {
    let mut w = W::new();
    w.bytes(&encode_proposal(&p.message));
    signature_enc(&mut w, &p.signature);
    w.finish()
}

fn decode_signed_proposal(bytes: &[u8]) -> Result<SignedProposal<PlxContext>, CodecError> {
    let mut r = R(bytes);
    let inner = r.bytes()?;
    let proposal = decode_proposal(&mut R(&inner))?;
    let signature = signature_dec(&mut r)?;
    Ok(SignedProposal::new(proposal, signature))
}

#[allow(dead_code)]
fn encode_commit_sig(w: &mut W, s: &CommitSignature<PlxContext>) {
    address_enc(w, &s.address);
    signature_enc(w, &s.signature);
}

#[allow(dead_code)]
fn decode_commit_sig(r: &mut R<'_>) -> Result<CommitSignature<PlxContext>, CodecError> {
    Ok(CommitSignature::new(address_dec(r)?, signature_dec(r)?))
}

fn encode_polka_sig(w: &mut W, s: &PolkaSignature<PlxContext>) {
    address_enc(w, &s.address);
    signature_enc(w, &s.signature);
}

fn decode_polka_sig(r: &mut R<'_>) -> Result<PolkaSignature<PlxContext>, CodecError> {
    Ok(PolkaSignature::new(address_dec(r)?, signature_dec(r)?))
}

fn encode_ext_commit_sig(w: &mut W, s: &ExtendedCommitSignature<PlxContext>) {
    address_enc(w, &s.address);
    signature_enc(w, &s.signature);
    match &s.extension {
        None => w.u8(0),
        Some(ext) => {
            w.u8(1);
            w.bytes(&ext.message);
            signature_enc(w, &ext.signature);
        }
    }
}

fn decode_ext_commit_sig(r: &mut R<'_>) -> Result<ExtendedCommitSignature<PlxContext>, CodecError> {
    let address = address_dec(r)?;
    let signature = signature_dec(r)?;
    let extension = match r.u8()? {
        0 => None,
        1 => {
            let message = Bytes::from(r.bytes()?);
            let sig = signature_dec(r)?;
            Some(SignedExtension::<PlxContext>::new(message, sig))
        }
        t => return Err(CodecError::Tag(t)),
    };
    Ok(ExtendedCommitSignature::new(address, signature, extension))
}

#[allow(dead_code)]
fn encode_commit_cert(w: &mut W, c: &CommitCertificate<PlxContext>) {
    height_enc(w, c.height);
    w.i64(round_enc(c.round));
    value_id_enc(w, &c.value_id);
    w.u32(c.commit_signatures.len() as u32);
    for s in &c.commit_signatures {
        encode_commit_sig(w, s);
    }
}

#[allow(dead_code)]
fn decode_commit_cert(r: &mut R<'_>) -> Result<CommitCertificate<PlxContext>, CodecError> {
    let height = height_dec(r)?;
    let round = round_dec(r.i64()?);
    let value_id = value_id_dec(r)?;
    let n = r.u32()? as usize;
    let mut commit_signatures = Vec::with_capacity(n);
    for _ in 0..n {
        commit_signatures.push(decode_commit_sig(r)?);
    }
    Ok(CommitCertificate {
        height,
        round,
        value_id,
        commit_signatures,
    })
}

fn encode_ext_cert(w: &mut W, c: &ExtendedCommitCertificate<PlxContext>) {
    height_enc(w, c.height);
    w.i64(round_enc(c.round));
    value_id_enc(w, &c.value_id);
    w.u32(c.commit_signatures.len() as u32);
    for s in &c.commit_signatures {
        encode_ext_commit_sig(w, s);
    }
}

fn decode_ext_cert(r: &mut R<'_>) -> Result<ExtendedCommitCertificate<PlxContext>, CodecError> {
    let height = height_dec(r)?;
    let round = round_dec(r.i64()?);
    let value_id = value_id_dec(r)?;
    let n = r.u32()? as usize;
    let mut commit_signatures = Vec::with_capacity(n);
    for _ in 0..n {
        commit_signatures.push(decode_ext_commit_sig(r)?);
    }
    Ok(ExtendedCommitCertificate {
        height,
        round,
        value_id,
        commit_signatures,
    })
}

fn encode_polka(w: &mut W, c: &PolkaCertificate<PlxContext>) {
    height_enc(w, c.height);
    w.i64(round_enc(c.round));
    value_id_enc(w, &c.value_id);
    w.u32(c.polka_signatures.len() as u32);
    for s in &c.polka_signatures {
        encode_polka_sig(w, s);
    }
}

fn decode_polka(r: &mut R<'_>) -> Result<PolkaCertificate<PlxContext>, CodecError> {
    let height = height_dec(r)?;
    let round = round_dec(r.i64()?);
    let value_id = value_id_dec(r)?;
    let n = r.u32()? as usize;
    let mut polka_signatures = Vec::with_capacity(n);
    for _ in 0..n {
        polka_signatures.push(decode_polka_sig(r)?);
    }
    Ok(PolkaCertificate {
        height,
        round,
        value_id,
        polka_signatures,
    })
}

fn encode_round_sig(w: &mut W, s: &RoundSignature<PlxContext>) {
    w.u8(vote_type_enc(s.vote_type));
    match &s.value_id {
        NilOrVal::Nil => w.u8(0),
        NilOrVal::Val(id) => {
            w.u8(1);
            value_id_enc(w, id);
        }
    }
    address_enc(w, &s.address);
    signature_enc(w, &s.signature);
}

fn decode_round_sig(r: &mut R<'_>) -> Result<RoundSignature<PlxContext>, CodecError> {
    let vote_type = vote_type_dec(r.u8()?)?;
    let value_id = match r.u8()? {
        0 => NilOrVal::Nil,
        1 => NilOrVal::Val(value_id_dec(r)?),
        t => return Err(CodecError::Tag(t)),
    };
    Ok(RoundSignature::new(
        vote_type,
        value_id,
        address_dec(r)?,
        signature_dec(r)?,
    ))
}

fn encode_round_cert(w: &mut W, c: &RoundCertificate<PlxContext>) {
    height_enc(w, c.height);
    w.i64(round_enc(c.round));
    w.u8(match c.cert_type {
        RoundCertificateType::Skip => 0,
        RoundCertificateType::Precommit => 1,
    });
    w.u32(c.round_signatures.len() as u32);
    for s in &c.round_signatures {
        encode_round_sig(w, s);
    }
}

fn decode_round_cert(r: &mut R<'_>) -> Result<RoundCertificate<PlxContext>, CodecError> {
    let height = height_dec(r)?;
    let round = round_dec(r.i64()?);
    let cert_type = match r.u8()? {
        0 => RoundCertificateType::Skip,
        1 => RoundCertificateType::Precommit,
        t => return Err(CodecError::Tag(t)),
    };
    let n = r.u32()? as usize;
    let mut round_signatures = Vec::with_capacity(n);
    for _ in 0..n {
        round_signatures.push(decode_round_sig(r)?);
    }
    Ok(RoundCertificate {
        height,
        round,
        cert_type,
        round_signatures,
    })
}

fn encode_proposed(v: &ProposedValue<PlxContext>) -> Bytes {
    let mut w = W::new();
    height_enc(&mut w, v.height);
    w.i64(round_enc(v.round));
    w.i64(round_enc(v.valid_round));
    address_enc(&mut w, &v.proposer);
    plx_value_enc(&mut w, &v.value);
    w.u8(match v.validity {
        Validity::Valid => 1,
        Validity::Invalid => 0,
    });
    w.finish()
}

fn decode_proposed(bytes: &[u8]) -> Result<ProposedValue<PlxContext>, CodecError> {
    let mut r = R(bytes);
    Ok(ProposedValue {
        height: height_dec(&mut r)?,
        round: round_dec(r.i64()?),
        valid_round: round_dec(r.i64()?),
        proposer: address_dec(&mut r)?,
        value: plx_value_dec(&mut r)?,
        validity: match r.u8()? {
            1 => Validity::Valid,
            0 => Validity::Invalid,
            t => return Err(CodecError::Tag(t)),
        },
    })
}

fn peer_enc(w: &mut W, p: &PeerId) {
    w.bytes(&p.to_bytes());
}

fn peer_dec(r: &mut R<'_>) -> Result<PeerId, CodecError> {
    let b = r.bytes()?;
    PeerId::from_bytes(&b).map_err(|_| CodecError::Other("peer id"))
}

impl Codec<PlxValue> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<PlxValue, Self::Error> {
        let v = ConsensusValue::decode_slice(&bytes).map_err(CodecError::Protocol)?;
        Ok(PlxValue(v))
    }

    fn encode(&self, msg: &PlxValue) -> Result<Bytes, Self::Error> {
        Ok(Bytes::from(msg.0.encode_vec()))
    }
}

impl Codec<ProposalPart> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<ProposalPart, Self::Error> {
        let mut r = R(&bytes);
        Ok(ProposalPart {
            height: height_dec(&mut r)?,
            round: round_dec(r.i64()?),
            proposer: address_dec(&mut r)?,
            value: plx_value_dec(&mut r)?,
        })
    }

    fn encode(&self, msg: &ProposalPart) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        height_enc(&mut w, msg.height);
        w.i64(round_enc(msg.round));
        address_enc(&mut w, &msg.proposer);
        plx_value_enc(&mut w, &msg.value);
        Ok(w.finish())
    }
}

impl Codec<SignedConsensusMsg<PlxContext>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<SignedConsensusMsg<PlxContext>, Self::Error> {
        wire::signed(bytes.len());
        let mut r = R(&bytes);
        match r.u8()? {
            1 => Ok(SignedConsensusMsg::Vote(decode_signed_vote(&r.bytes()?)?)),
            2 => Ok(SignedConsensusMsg::Proposal(decode_signed_proposal(
                &r.bytes()?,
            )?)),
            t => Err(CodecError::Tag(t)),
        }
    }

    fn encode(&self, msg: &SignedConsensusMsg<PlxContext>) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        match msg {
            SignedConsensusMsg::Vote(v) => {
                w.u8(1);
                w.bytes(&encode_signed_vote(v));
            }
            SignedConsensusMsg::Proposal(p) => {
                w.u8(2);
                w.bytes(&encode_signed_proposal(p));
            }
        }
        Ok(w.finish())
    }
}

impl Codec<ProposedValue<PlxContext>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<ProposedValue<PlxContext>, Self::Error> {
        decode_proposed(&bytes)
    }

    fn encode(&self, msg: &ProposedValue<PlxContext>) -> Result<Bytes, Self::Error> {
        Ok(encode_proposed(msg))
    }
}

impl Codec<PolkaCertificate<PlxContext>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<PolkaCertificate<PlxContext>, Self::Error> {
        decode_polka(&mut R(&bytes))
    }

    fn encode(&self, msg: &PolkaCertificate<PlxContext>) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        encode_polka(&mut w, msg);
        Ok(w.finish())
    }
}

impl Codec<StreamMessage<ProposalPart>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<StreamMessage<ProposalPart>, Self::Error> {
        wire::other(bytes.len());
        let mut r = R(&bytes);
        let stream_id = StreamId::new(Bytes::from(r.bytes()?));
        let sequence = r.u64()?;
        let content = match r.u8()? {
            0 => StreamContent::Data(ProposalPart {
                height: height_dec(&mut r)?,
                round: round_dec(r.i64()?),
                proposer: address_dec(&mut r)?,
                value: plx_value_dec(&mut r)?,
            }),
            1 => StreamContent::Fin,
            t => return Err(CodecError::Tag(t)),
        };
        Ok(StreamMessage::new(stream_id, sequence, content))
    }

    fn encode(&self, msg: &StreamMessage<ProposalPart>) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        w.bytes(&msg.stream_id.to_bytes());
        w.u64(msg.sequence);
        match &msg.content {
            StreamContent::Data(part) => {
                w.u8(0);
                height_enc(&mut w, part.height);
                w.i64(round_enc(part.round));
                address_enc(&mut w, &part.proposer);
                plx_value_enc(&mut w, &part.value);
            }
            StreamContent::Fin => w.u8(1),
        }
        Ok(w.finish())
    }
}

impl Codec<ValidatorProof<PlxContext>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<ValidatorProof<PlxContext>, Self::Error> {
        let mut r = R(&bytes);
        let public_key = r.bytes()?;
        let peer_id = r.bytes()?;
        let signature = signature_dec(&mut r)?;
        Ok(ValidatorProof::new(public_key, peer_id, signature))
    }

    fn encode(&self, msg: &ValidatorProof<PlxContext>) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        w.bytes(&msg.public_key);
        w.bytes(&msg.peer_id);
        signature_enc(&mut w, &msg.signature);
        Ok(w.finish())
    }
}

impl Codec<LivenessMsg<PlxContext>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<LivenessMsg<PlxContext>, Self::Error> {
        wire::signed(bytes.len());
        let mut r = R(&bytes);
        match r.u8()? {
            1 => Ok(LivenessMsg::Vote(decode_signed_vote(&r.bytes()?)?)),
            2 => Ok(LivenessMsg::PolkaCertificate(decode_polka(&mut R(
                &r.bytes()?
            ))?)),
            3 => Ok(LivenessMsg::SkipRoundCertificate(decode_round_cert(
                &mut R(&r.bytes()?),
            )?)),
            t => Err(CodecError::Tag(t)),
        }
    }

    fn encode(&self, msg: &LivenessMsg<PlxContext>) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        match msg {
            LivenessMsg::Vote(v) => {
                w.u8(1);
                w.bytes(&encode_signed_vote(v));
            }
            LivenessMsg::PolkaCertificate(c) => {
                w.u8(2);
                let mut inner = W::new();
                encode_polka(&mut inner, c);
                w.bytes(&inner.0);
            }
            LivenessMsg::SkipRoundCertificate(c) => {
                w.u8(3);
                let mut inner = W::new();
                encode_round_cert(&mut inner, c);
                w.bytes(&inner.0);
            }
        }
        Ok(w.finish())
    }
}

impl Codec<Status<PlxContext>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<Status<PlxContext>, Self::Error> {
        let mut r = R(&bytes);
        Ok(Status {
            peer_id: peer_dec(&mut r)?,
            tip_height: height_dec(&mut r)?,
            history_min_height: height_dec(&mut r)?,
        })
    }

    fn encode(&self, msg: &Status<PlxContext>) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        peer_enc(&mut w, &msg.peer_id);
        height_enc(&mut w, msg.tip_height);
        height_enc(&mut w, msg.history_min_height);
        Ok(w.finish())
    }
}

impl Codec<Request<PlxContext>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<Request<PlxContext>, Self::Error> {
        let mut r = R(&bytes);
        match r.u8()? {
            1 => {
                let start = height_dec(&mut r)?;
                let end = height_dec(&mut r)?;
                Ok(Request::ValueRequest(sync::ValueRequest::new(start..=end)))
            }
            t => Err(CodecError::Tag(t)),
        }
    }

    fn encode(&self, msg: &Request<PlxContext>) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        match msg {
            Request::ValueRequest(req) => {
                w.u8(1);
                height_enc(&mut w, *req.range.start());
                height_enc(&mut w, *req.range.end());
            }
        }
        Ok(w.finish())
    }
}

fn encode_raw_decided(w: &mut W, v: &RawDecidedValue<PlxContext>) {
    w.bytes(&v.value_bytes);
    encode_ext_cert(w, &v.certificate);
}

fn decode_raw_decided(r: &mut R<'_>) -> Result<RawDecidedValue<PlxContext>, CodecError> {
    Ok(RawDecidedValue {
        value_bytes: Bytes::from(r.bytes()?),
        certificate: decode_ext_cert(r)?,
    })
}

impl Codec<Response<PlxContext>> for PlxCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<Response<PlxContext>, Self::Error> {
        let mut r = R(&bytes);
        match r.u8()? {
            1 => {
                let start_height = height_dec(&mut r)?;
                let n = r.u32()? as usize;
                let mut values = Vec::with_capacity(n);
                for _ in 0..n {
                    values.push(decode_raw_decided(&mut r)?);
                }
                Ok(Response::ValueResponse(sync::ValueResponse::new(
                    start_height,
                    values,
                )))
            }
            t => Err(CodecError::Tag(t)),
        }
    }

    fn encode(&self, msg: &Response<PlxContext>) -> Result<Bytes, Self::Error> {
        let mut w = W::new();
        match msg {
            Response::ValueResponse(resp) => {
                w.u8(1);
                height_enc(&mut w, resp.start_height);
                w.u32(resp.values.len() as u32);
                for v in &resp.values {
                    encode_raw_decided(&mut w, v);
                }
            }
        }
        Ok(w.finish())
    }
}

impl HasEncodedLen<Response<PlxContext>> for PlxCodec {
    fn encoded_len(&self, msg: &Response<PlxContext>) -> Result<usize, CodecError> {
        self.encode(msg).map(|b| b.len())
    }
}
