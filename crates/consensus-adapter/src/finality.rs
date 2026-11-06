//! Tiered finality (ADR 0031, Q-CRY-5). Consensus votes sign with the
//! classical part of each validator key; after decide, each validator signs
//! `(height, value id)` once with its full (hybrid) key and sends it to `k`
//! collectors. 2f+1 such signatures form a [`FinalityCertificate`].
//!
//! Safety of the certificate does not depend on the classical votes: an honest
//! validator finality-signs only what it decided, at most once per height, and
//! any two 2f+1 quorums share an honest validator. A forger who breaks Ed25519
//! in real time can split honest nodes' local decisions (liveness of the
//! certificate), but cannot make two conflicting certificates.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use commitments::Digest;
use crypto_suite::{verify, SigError, SuitePolicy, SuitePublicKey, SuiteSignature, SuiteSigningKey};

pub const CTX_FINALITY: &[u8] = b"plx/finality/v1";

/// `height_le ‖ value_id`.
pub fn finality_msg(height: u64, value_id: &Digest) -> Vec<u8> {
    let mut m = height.to_le_bytes().to_vec();
    m.extend_from_slice(&value_id.0);
    m
}

/// Smallest count strictly above 2/3 of `n` (equal voting power).
pub fn quorum(n: usize) -> usize {
    2 * n / 3 + 1
}

/// Collectors for `height`: `k` validators starting at `height mod n`.
/// `k = f + 1` guarantees an honest collector.
pub fn collectors(height: u64, n: usize, k: usize) -> Vec<usize> {
    collectors_round(height, n, k, 0)
}

/// Collectors for failover round `round`: the next `k` validators after the
/// previous rounds' (ADR 0031). Round 0 is [`collectors`].
pub fn collectors_round(height: u64, n: usize, k: usize, round: u32) -> Vec<usize> {
    let start = height as usize + round as usize * k;
    (0..k.min(n)).map(|j| (start + j) % n).collect()
}

/// Rounds needed for every validator to have been a collector once.
pub fn max_rounds(n: usize, k: usize) -> u32 {
    n.div_ceil(k.max(1)) as u32
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalitySig {
    pub height: u64,
    pub value_id: Digest,
    /// Index into the roster.
    pub signer: u16,
    pub sig: SuiteSignature,
}

impl FinalitySig {
    pub fn sign(key: &SuiteSigningKey, signer: u16, height: u64, value_id: Digest) -> Self {
        let sig = key.sign(CTX_FINALITY, &finality_msg(height, &value_id));
        Self { height, value_id, signer, sig }
    }

    /// `height ‖ value_id ‖ signer ‖ sig`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = finality_msg(self.height, &self.value_id);
        out.extend_from_slice(&self.signer.to_le_bytes());
        out.extend_from_slice(&self.sig.encode());
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 42 {
            return None;
        }
        Some(Self {
            height: u64::from_le_bytes(b[..8].try_into().ok()?),
            value_id: Digest(b[8..40].try_into().ok()?),
            signer: u16::from_le_bytes(b[40..42].try_into().ok()?),
            sig: SuiteSignature::decode(&b[42..])?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinalityError {
    #[error("signer {0} not in the roster")]
    UnknownSigner(u16),
    #[error("signer {0} listed twice")]
    Duplicate(u16),
    #[error("signer {signer}: {err}")]
    Signature { signer: u16, err: SigError },
    #[error("{have} signers, quorum is {need}")]
    NoQuorum { have: usize, need: usize },
    /// Same signer, same height, two values: evidence of equivocation.
    #[error("signer {0} signed two values at one height")]
    Equivocation(u16),
}

/// 2f+1 finality signatures on one `(height, value id)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityCertificate {
    pub height: u64,
    pub value_id: Digest,
    pub sigs: Vec<(u16, SuiteSignature)>,
}

impl FinalityCertificate {
    /// Check every signature under `policy` and the quorum (equal power).
    pub fn verify(&self, policy: SuitePolicy, roster: &[SuitePublicKey]) -> Result<(), FinalityError> {
        let msg = finality_msg(self.height, &self.value_id);
        let mut seen = BTreeSet::new();
        for (signer, sig) in &self.sigs {
            let pk = roster.get(*signer as usize).ok_or(FinalityError::UnknownSigner(*signer))?;
            if !seen.insert(*signer) {
                return Err(FinalityError::Duplicate(*signer));
            }
            verify(policy, pk, CTX_FINALITY, &msg, sig)
                .map_err(|err| FinalityError::Signature { signer: *signer, err })?;
        }
        let need = quorum(roster.len());
        if seen.len() < need {
            return Err(FinalityError::NoQuorum { have: seen.len(), need });
        }
        Ok(())
    }

    /// Encoded size: what a light client or syncing node downloads per height.
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    /// `height ‖ value_id ‖ u32 count ‖ (u16 signer ‖ u32 len ‖ sig)*`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = finality_msg(self.height, &self.value_id);
        out.extend_from_slice(&(self.sigs.len() as u32).to_le_bytes());
        for (i, sig) in &self.sigs {
            let b = sig.encode();
            out.extend_from_slice(&i.to_le_bytes());
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(&b);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let take = |b: &mut &[u8], n: usize| -> Option<Vec<u8>> {
            if b.len() < n {
                return None;
            }
            let (x, rest) = b.split_at(n);
            *b = rest;
            Some(x.to_vec())
        };
        let mut r = b;
        let height = u64::from_le_bytes(take(&mut r, 8)?.try_into().ok()?);
        let value_id = Digest(take(&mut r, 32)?.try_into().ok()?);
        let count = u32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?) as usize;
        if count > 4096 {
            return None;
        }
        let mut sigs = Vec::with_capacity(count);
        for _ in 0..count {
            let i = u16::from_le_bytes(take(&mut r, 2)?.try_into().ok()?);
            let len = u32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?) as usize;
            sigs.push((i, SuiteSignature::decode(&take(&mut r, len)?)?));
        }
        r.is_empty().then_some(Self { height, value_id, sigs })
    }
}

/// Assembles certificates from incoming finality signatures. Each signature
/// is verified on arrival; a certificate is emitted once per height.
pub struct Collector {
    policy: SuitePolicy,
    roster: Arc<Vec<SuitePublicKey>>,
    pending: BTreeMap<u64, BTreeMap<u16, (Digest, SuiteSignature)>>,
    done: BTreeSet<u64>,
}

impl Collector {
    pub fn new(policy: SuitePolicy, roster: Arc<Vec<SuitePublicKey>>) -> Self {
        Self { policy, roster, pending: BTreeMap::new(), done: BTreeSet::new() }
    }

    pub fn add(&mut self, fs: FinalitySig) -> Result<Option<FinalityCertificate>, FinalityError> {
        let pk = self.roster.get(fs.signer as usize).ok_or(FinalityError::UnknownSigner(fs.signer))?;
        verify(self.policy, pk, CTX_FINALITY, &finality_msg(fs.height, &fs.value_id), &fs.sig)
            .map_err(|err| FinalityError::Signature { signer: fs.signer, err })?;
        let at = self.pending.entry(fs.height).or_default();
        if let Some((v, _)) = at.get(&fs.signer) {
            return if *v == fs.value_id { Ok(None) } else { Err(FinalityError::Equivocation(fs.signer)) };
        }
        at.insert(fs.signer, (fs.value_id, fs.sig));
        if self.done.contains(&fs.height) {
            return Ok(None);
        }
        let sigs: Vec<(u16, SuiteSignature)> = at
            .iter()
            .filter(|(_, (v, _))| *v == fs.value_id)
            .map(|(i, (_, s))| (*i, s.clone()))
            .collect();
        if sigs.len() < quorum(self.roster.len()) {
            return Ok(None);
        }
        self.done.insert(fs.height);
        Ok(Some(FinalityCertificate { height: fs.height, value_id: fs.value_id, sigs }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::CryptoSuiteId::{ClassicalV0, HybridV1};

    fn roster(n: usize) -> (Vec<SuiteSigningKey>, Arc<Vec<SuitePublicKey>>) {
        let keys: Vec<_> = (0..n).map(|i| SuiteSigningKey::from_seed(HybridV1, [i as u8 + 1; 32])).collect();
        let pks = Arc::new(keys.iter().map(|k| k.public()).collect());
        (keys, pks)
    }

    #[test]
    fn quorum_and_collectors() {
        assert_eq!((quorum(4), quorum(7), quorum(100)), (3, 5, 67));
        assert_eq!(collectors(5, 4, 2), vec![1, 2]);
        assert_eq!(collectors(1, 4, 9), vec![1, 2, 3, 0]);
        assert_eq!(collectors_round(5, 4, 1, 1), vec![2]);
        assert_eq!(collectors_round(5, 4, 2, 1), vec![3, 0]);
        assert_eq!((max_rounds(4, 1), max_rounds(4, 2), max_rounds(7, 3)), (4, 2, 3));
    }

    #[test]
    fn certificate_forms_at_quorum_and_verifies() {
        let (keys, pks) = roster(4);
        let mut c = Collector::new(SuitePolicy::HYBRID, pks.clone());
        let id = Digest([7; 32]);
        let mut cert = None;
        for (i, k) in keys.iter().enumerate() {
            let fs = FinalitySig::sign(k, i as u16, 9, id);
            assert_eq!(FinalitySig::decode(&fs.encode()), Some(fs.clone()));
            if let Some(c) = c.add(fs).unwrap() {
                assert_eq!(i, 2, "emitted at the third signature");
                cert = Some(c);
            }
        }
        let cert = cert.unwrap();
        assert_eq!(cert.verify(SuitePolicy::HYBRID, &pks), Ok(()));
        assert_eq!(FinalityCertificate::decode(&cert.encode()), Some(cert.clone()));
        let mut short = cert.clone();
        short.sigs.pop();
        assert!(matches!(short.verify(SuitePolicy::HYBRID, &pks), Err(FinalityError::NoQuorum { .. })));
        let mut dup = short.clone();
        dup.sigs.push(dup.sigs[0].clone());
        assert!(matches!(dup.verify(SuitePolicy::HYBRID, &pks), Err(FinalityError::Duplicate(_))));
        let mut other = cert.clone();
        other.value_id = Digest([8; 32]);
        assert!(matches!(other.verify(SuitePolicy::HYBRID, &pks), Err(FinalityError::Signature { .. })));
    }

    /// Classical-tagged finality signatures (an Ed25519-only forger) are
    /// rejected under the hybrid policy, as are vote-context signatures.
    #[test]
    fn classical_or_cross_context_signatures_rejected() {
        let (keys, pks) = roster(4);
        let mut c = Collector::new(SuitePolicy::HYBRID, pks.clone());
        let id = Digest([7; 32]);
        let forged = SuiteSigningKey::from_seed(ClassicalV0, [1; 32]);
        let fs = FinalitySig { height: 1, value_id: id, signer: 0, sig: forged.sign(CTX_FINALITY, &finality_msg(1, &id)) };
        assert!(c.add(fs).is_err());
        let vote_sig = keys[0].sign(b"plx/cons/vote", &finality_msg(1, &id));
        assert!(c.add(FinalitySig { height: 1, value_id: id, signer: 0, sig: vote_sig }).is_err());
    }

    /// Two conflicting certificates need a validator to sign both values:
    /// caught as equivocation; with honest signers they cannot both reach quorum.
    #[test]
    fn equivocation_detected() {
        let (keys, pks) = roster(4);
        let mut c = Collector::new(SuitePolicy::HYBRID, pks);
        c.add(FinalitySig::sign(&keys[0], 0, 3, Digest([1; 32]))).unwrap();
        assert_eq!(
            c.add(FinalitySig::sign(&keys[0], 0, 3, Digest([2; 32]))),
            Err(FinalityError::Equivocation(0))
        );
    }
}
