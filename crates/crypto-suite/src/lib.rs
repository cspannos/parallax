//! Suite-tagged signatures: classical Ed25519 or hybrid Ed25519 + ML-DSA-65
//! (Phase 7, ADR 0030).
//!
//! Rules:
//! - A key carries its suite. A hybrid key only accepts hybrid signatures, and
//!   a hybrid signature is valid only if **both** components verify.
//! - Signed bytes are `SIG_DOMAIN ‖ suite ‖ len ‖ context ‖ msg`, so relabelling
//!   a signature as another suite breaks both components, and a signature for
//!   one context does not verify in another.
//! - A [`SuitePolicy`] names the minimum suite a verifier accepts; anything
//!   weaker is a downgrade and is rejected.
//!
//! Hybrid means an attacker must break **both** Ed25519 and ML-DSA-65. It is
//! not a claim that the system is post-quantum secure (`post-quantum.md`).
#![forbid(unsafe_code)]

pub mod kex;

use ml_dsa::signature::Keypair;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature as MlDsaSig, SigningKey as MlDsaSk, VerifyingKey as MlDsaVk};
use protocol_types::CryptoSuiteId;
use sha2::{Digest as _, Sha256};

pub use protocol_types::AlgorithmId;

/// Domain of every suite signature.
pub const SIG_DOMAIN: &[u8] = b"plx/sig/v1";
/// FIPS 204 context string for the ML-DSA component.
const MLDSA_CTX: &[u8] = b"plx/v1";

pub const ED25519_PK_BYTES: usize = 32;
pub const ED25519_SIG_BYTES: usize = 64;
pub const MLDSA65_PK_BYTES: usize = 1952;
pub const MLDSA65_SIG_BYTES: usize = 3309;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    #[error("suite below policy minimum (downgrade)")]
    Downgrade,
    #[error("signature suite does not match the key's suite")]
    SuiteMismatch,
    #[error("components do not match the suite")]
    Malformed,
    #[error("Ed25519 component invalid")]
    Ed25519,
    #[error("ML-DSA-65 component invalid")]
    MlDsa,
}

/// The weakest suite a verifier accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuitePolicy {
    pub min: CryptoSuiteId,
}

impl SuitePolicy {
    pub const CLASSICAL: Self = Self { min: CryptoSuiteId::ClassicalV0 };
    pub const HYBRID: Self = Self { min: CryptoSuiteId::HybridV1 };
}

/// The bytes both components sign.
pub fn signed_bytes(suite: CryptoSuiteId, context: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(SIG_DOMAIN.len() + 2 + 4 + context.len() + msg.len());
    b.extend_from_slice(SIG_DOMAIN);
    b.extend_from_slice(&suite.code().to_le_bytes());
    b.extend_from_slice(&(context.len() as u32).to_le_bytes());
    b.extend_from_slice(context);
    b.extend_from_slice(msg);
    b
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SuitePublicKey {
    pub suite: CryptoSuiteId,
    pub ed25519: [u8; ED25519_PK_BYTES],
    /// Present iff the suite has an ML-DSA component.
    pub mldsa65: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SuiteSignature {
    pub suite: CryptoSuiteId,
    pub ed25519: [u8; ED25519_SIG_BYTES],
    pub mldsa65: Option<Vec<u8>>,
}

/// Signing key bound to one suite.
#[derive(Clone)]
pub struct SuiteSigningKey {
    suite: CryptoSuiteId,
    ed25519: ed25519_consensus::SigningKey,
    mldsa65: Option<MlDsaSk<MlDsa65>>,
}

impl std::fmt::Debug for SuiteSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuiteSigningKey").field("suite", &self.suite).finish_non_exhaustive()
    }
}

impl SuiteSigningKey {
    /// Deterministic from a 32-byte secret seed. The Ed25519 key is the seed
    /// itself (so a classical key equals today's validator key); the ML-DSA
    /// seed is `SHA-256("plx/mldsa65-seed/v1" ‖ seed)`.
    pub fn from_seed(suite: CryptoSuiteId, seed: [u8; 32]) -> Self {
        let mldsa65 = suite.has_pq_components().then(|| {
            let s: [u8; 32] = Sha256::new()
                .chain_update(b"plx/mldsa65-seed/v1")
                .chain_update(seed)
                .finalize()
                .into();
            MlDsaSk::<MlDsa65>::from_seed(&s.into())
        });
        Self { suite, ed25519: ed25519_consensus::SigningKey::from(seed), mldsa65 }
    }

    pub fn suite(&self) -> CryptoSuiteId {
        self.suite
    }

    /// The classical part alone: same Ed25519 key, `ClassicalV0` tag (tiered
    /// finality, Q-CRY-5). Its signatures sign classical-tagged bytes, so they
    /// never verify as (part of) a hybrid signature, and vice versa.
    pub fn classical(&self) -> SuiteSigningKey {
        Self { suite: CryptoSuiteId::ClassicalV0, ed25519: self.ed25519.clone(), mldsa65: None }
    }

    pub fn public(&self) -> SuitePublicKey {
        SuitePublicKey {
            suite: self.suite,
            ed25519: self.ed25519.verification_key().to_bytes(),
            mldsa65: self.mldsa65.as_ref().map(|k| k.verifying_key().encode().to_vec()),
        }
    }

    pub fn sign(&self, context: &[u8], msg: &[u8]) -> SuiteSignature {
        let bytes = signed_bytes(self.suite, context, msg);
        SuiteSignature {
            suite: self.suite,
            ed25519: self.ed25519.sign(&bytes).to_bytes(),
            mldsa65: self.mldsa65.as_ref().map(|k| {
                k.expanded_key()
                    .sign_deterministic(&bytes, MLDSA_CTX)
                    .expect("ctx ≤ 255 bytes")
                    .encode()
                    .to_vec()
            }),
        }
    }
}

/// Verify `sig` on `(context, msg)` under `pk`, refusing anything weaker than
/// `policy`.
pub fn verify(
    policy: SuitePolicy,
    pk: &SuitePublicKey,
    context: &[u8],
    msg: &[u8],
    sig: &SuiteSignature,
) -> Result<(), SigError> {
    if sig.suite < policy.min || pk.suite < policy.min {
        return Err(SigError::Downgrade);
    }
    if sig.suite != pk.suite {
        return Err(SigError::SuiteMismatch);
    }
    let pq = sig.suite.has_pq_components();
    if pq != sig.mldsa65.is_some() || pq != pk.mldsa65.is_some() {
        return Err(SigError::Malformed);
    }
    let bytes = signed_bytes(sig.suite, context, msg);
    let vk = ed25519_consensus::VerificationKey::try_from(pk.ed25519).map_err(|_| SigError::Ed25519)?;
    vk.verify(&ed25519_consensus::Signature::from(sig.ed25519), &bytes)
        .map_err(|_| SigError::Ed25519)?;
    if let (Some(pk_pq), Some(sig_pq)) = (&pk.mldsa65, &sig.mldsa65) {
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk_pq.as_slice()).map_err(|_| SigError::MlDsa)?;
        let vk = MlDsaVk::<MlDsa65>::decode(&enc);
        let s = MlDsaSig::<MlDsa65>::try_from(sig_pq.as_slice()).map_err(|_| SigError::MlDsa)?;
        if !vk.verify_with_context(&bytes, MLDSA_CTX, &s) {
            return Err(SigError::MlDsa);
        }
    }
    Ok(())
}

fn put_opt(out: &mut Vec<u8>, v: &Option<Vec<u8>>) {
    match v {
        None => out.extend_from_slice(&0u32.to_le_bytes()),
        Some(b) => {
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(b);
        }
    }
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if b.len() < n {
        return None;
    }
    let (x, rest) = b.split_at(n);
    *b = rest;
    Some(x)
}

fn take_opt(b: &mut &[u8], want: usize) -> Option<Option<Vec<u8>>> {
    let n = u32::from_le_bytes(take(b, 4)?.try_into().ok()?) as usize;
    match n {
        0 => Some(None),
        n if n == want => Some(Some(take(b, n)?.to_vec())),
        _ => None,
    }
}

impl SuitePublicKey {
    /// The classical part alone (see [`SuiteSigningKey::classical`]).
    pub fn classical(&self) -> SuitePublicKey {
        SuitePublicKey { suite: CryptoSuiteId::ClassicalV0, ed25519: self.ed25519, mldsa65: None }
    }

    /// `suite_u16 ‖ ed25519 ‖ u32 len ‖ mldsa65`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.suite.code().to_le_bytes().to_vec();
        out.extend_from_slice(&self.ed25519);
        put_opt(&mut out, &self.mldsa65);
        out
    }

    pub fn decode(mut b: &[u8]) -> Option<Self> {
        let suite = CryptoSuiteId::from_code(u16::from_le_bytes(take(&mut b, 2)?.try_into().ok()?))?;
        let ed25519 = take(&mut b, ED25519_PK_BYTES)?.try_into().ok()?;
        let mldsa65 = take_opt(&mut b, MLDSA65_PK_BYTES)?;
        b.is_empty().then_some(Self { suite, ed25519, mldsa65 })
    }
}

impl SuiteSignature {
    /// `suite_u16 ‖ ed25519 ‖ u32 len ‖ mldsa65`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.suite.code().to_le_bytes().to_vec();
        out.extend_from_slice(&self.ed25519);
        put_opt(&mut out, &self.mldsa65);
        out
    }

    pub fn decode(mut b: &[u8]) -> Option<Self> {
        let suite = CryptoSuiteId::from_code(u16::from_le_bytes(take(&mut b, 2)?.try_into().ok()?))?;
        let ed25519 = take(&mut b, ED25519_SIG_BYTES)?.try_into().ok()?;
        let mldsa65 = take_opt(&mut b, MLDSA65_SIG_BYTES)?;
        b.is_empty().then_some(Self { suite, ed25519, mldsa65 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"plx/cons/vote";
    fn keys() -> (SuiteSigningKey, SuiteSigningKey) {
        (
            SuiteSigningKey::from_seed(CryptoSuiteId::ClassicalV0, [7; 32]),
            SuiteSigningKey::from_seed(CryptoSuiteId::HybridV1, [7; 32]),
        )
    }

    #[test]
    fn classical_and_hybrid_round_trip() {
        let (c, h) = keys();
        for (k, policy) in [(&c, SuitePolicy::CLASSICAL), (&h, SuitePolicy::CLASSICAL), (&h, SuitePolicy::HYBRID)] {
            let sig = k.sign(CTX, b"msg");
            assert_eq!(verify(policy, &k.public(), CTX, b"msg", &sig), Ok(()));
            assert_eq!(SuiteSignature::decode(&sig.encode()), Some(sig.clone()));
            assert_eq!(SuitePublicKey::decode(&k.public().encode()), Some(k.public()));
        }
        // Classical key = today's Ed25519 key from the same seed.
        assert_eq!(c.public().ed25519, h.public().ed25519);
        assert_eq!(h.sign(CTX, b"m").encode().len(), 2 + 64 + 4 + MLDSA65_SIG_BYTES);
        assert_eq!(c.sign(CTX, b"m").encode().len(), 2 + 64 + 4);
    }

    /// Tiered finality: the classical projection of a hybrid key signs votes;
    /// those signatures do not verify under the hybrid key, and a hybrid
    /// signature does not verify under the projection.
    #[test]
    fn classical_projection_is_domain_separated() {
        let (_, h) = keys();
        let c = h.classical();
        assert_eq!(c.public(), h.public().classical());
        let cs = c.sign(CTX, b"msg");
        assert_eq!(verify(SuitePolicy::CLASSICAL, &c.public(), CTX, b"msg", &cs), Ok(()));
        assert!(verify(SuitePolicy::CLASSICAL, &h.public(), CTX, b"msg", &cs).is_err());
        let mut hs = h.sign(CTX, b"msg");
        assert!(verify(SuitePolicy::CLASSICAL, &c.public(), CTX, b"msg", &hs).is_err());
        hs.suite = CryptoSuiteId::ClassicalV0;
        hs.mldsa65 = None;
        assert!(verify(SuitePolicy::CLASSICAL, &c.public(), CTX, b"msg", &hs).is_err());
    }

    #[test]
    fn classical_rejected_under_hybrid_policy() {
        let (c, _) = keys();
        let sig = c.sign(CTX, b"msg");
        assert_eq!(verify(SuitePolicy::HYBRID, &c.public(), CTX, b"msg", &sig), Err(SigError::Downgrade));
    }

    /// Strip the ML-DSA part and relabel as classical: rejected whatever the
    /// policy, because the key is hybrid and the Ed25519 part signed the
    /// hybrid-tagged bytes.
    #[test]
    fn relabel_and_strip_downgrade_rejected() {
        let (_, h) = keys();
        let mut sig = h.sign(CTX, b"msg");
        sig.mldsa65 = None;
        assert_eq!(verify(SuitePolicy::CLASSICAL, &h.public(), CTX, b"msg", &sig), Err(SigError::Malformed));
        sig.suite = CryptoSuiteId::ClassicalV0;
        assert_eq!(verify(SuitePolicy::CLASSICAL, &h.public(), CTX, b"msg", &sig), Err(SigError::SuiteMismatch));
        let mut pk = h.public();
        pk.suite = CryptoSuiteId::ClassicalV0;
        pk.mldsa65 = None;
        assert_eq!(verify(SuitePolicy::CLASSICAL, &pk, CTX, b"msg", &sig), Err(SigError::Ed25519));
    }

    /// An attacker holding only the Ed25519 secret (classical break) cannot
    /// produce a hybrid signature.
    #[test]
    fn ed25519_break_alone_does_not_forge_hybrid() {
        let (_, h) = keys();
        let attacker = SuiteSigningKey::from_seed(CryptoSuiteId::HybridV1, [7; 32]);
        // Same Ed25519 key, but a different ML-DSA key: re-derive with another seed
        // for the PQ half by signing with a different hybrid key and splicing.
        let other = SuiteSigningKey::from_seed(CryptoSuiteId::HybridV1, [8; 32]);
        let mut forged = attacker.sign(CTX, b"msg");
        forged.mldsa65 = other.sign(CTX, b"msg").mldsa65;
        assert_eq!(verify(SuitePolicy::HYBRID, &h.public(), CTX, b"msg", &forged), Err(SigError::MlDsa));
    }

    #[test]
    fn tamper_and_cross_context_rejected() {
        let (_, h) = keys();
        let sig = h.sign(CTX, b"msg");
        assert_eq!(verify(SuitePolicy::HYBRID, &h.public(), b"other", b"msg", &sig), Err(SigError::Ed25519));
        assert_eq!(verify(SuitePolicy::HYBRID, &h.public(), CTX, b"msh", &sig), Err(SigError::Ed25519));
        let mut t = sig.clone();
        t.mldsa65.as_mut().unwrap()[100] ^= 1;
        assert!(matches!(verify(SuitePolicy::HYBRID, &h.public(), CTX, b"msg", &t), Err(SigError::MlDsa)));
        assert_eq!(SuiteSignature::decode(&sig.encode()[..100]), None);
        let mut bad = sig.encode();
        bad[0] = 9;
        assert_eq!(SuiteSignature::decode(&bad), None, "unknown suite code");
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use std::time::Instant;

    /// Timing, not a criterion bench: `cargo test -p crypto-suite --release -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing; run in release"]
    fn sign_verify_timing() {
        let msg = [5u8; 120]; // ~ a vote's sign bytes
        for suite in [CryptoSuiteId::ClassicalV0, CryptoSuiteId::HybridV1] {
            let n = 2_000u32;
            let t = Instant::now();
            let mut k = SuiteSigningKey::from_seed(suite, [1; 32]);
            for i in 0..50u8 {
                k = SuiteSigningKey::from_seed(suite, [i; 32]);
            }
            let keygen = t.elapsed() / 51;
            let t = Instant::now();
            let mut sig = k.sign(b"ctx", &msg);
            for _ in 0..n {
                sig = k.sign(b"ctx", &msg);
            }
            let sign = t.elapsed() / (n + 1);
            let pk = k.public();
            let t = Instant::now();
            for _ in 0..n {
                verify(SuitePolicy::CLASSICAL, &pk, b"ctx", &msg, &sig).unwrap();
            }
            let ver = t.elapsed() / n;
            eprintln!(
                "{suite:?}: keygen {:?}, sign {:?}, verify {:?}, pk {} B, sig {} B",
                keygen,
                sign,
                ver,
                pk.encode().len(),
                sig.encode().len()
            );
        }
    }
}
