//! Suite-tagged authenticated key exchange and an AEAD session (Phase 7,
//! ADR 0030). Sans-I/O: callers move the three messages.
//!
//! ```text
//! C → S  hello   = KEX_DOMAIN ‖ suite ‖ x25519_c ‖ opt(ml-kem ek)
//! S → C  reply   = suite ‖ x25519_s ‖ opt(ml-kem ct) ‖ pk_s ‖ sig_s(th1)
//! C → S  finish  = pk_c ‖ sig_c(th2 ‖ pk_c)
//! th1 = SHA-256(hello ‖ reply-before-sig), th2 = SHA-256(th1 ‖ sig_s)
//! keys = HKDF-SHA256(salt = th1, ikm = ss_x25519 ‖ ss_mlkem, info = dir)
//! ```
//!
//! - Hybrid: both shared secrets feed the key, so it stays secret unless
//!   **both** X25519 and ML-KEM-768 fall. Both sides sign the transcript with
//!   their suite keys (hybrid keys: Ed25519 **and** ML-DSA-65).
//! - Downgrade: the responder refuses a hello below its [`SuitePolicy`]; the
//!   initiator refuses a reply whose suite differs from what it offered; and
//!   because the signatures cover the whole transcript, a man in the middle
//!   who rewrites the offered suite (or strips the ML-KEM key) breaks them.
//! - Ephemeral keys per connection (forward secrecy for both components).
//!
//! Experimental: no key confirmation beyond the signatures, no rekeying, no
//! session resumption.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use ml_kem::{Decapsulate, EncapsulationKey, KeyExport, MlKem768, TryKeyInit};
use protocol_types::CryptoSuiteId;
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey as XPub, StaticSecret};

use super::{put_opt, take, take_opt, verify, SigError, SuitePolicy, SuitePublicKey, SuiteSignature, SuiteSigningKey};

pub const KEX_DOMAIN: &[u8] = b"plx/kex/v1";
const CTX_SERVER: &[u8] = b"plx/kex/v1/server";
const CTX_CLIENT: &[u8] = b"plx/kex/v1/client";
pub const MLKEM768_EK_BYTES: usize = 1184;
pub const MLKEM768_CT_BYTES: usize = 1088;
/// AEAD tag added to each sealed frame.
pub const TAG_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KexError {
    #[error("offered suite below policy minimum (downgrade)")]
    Downgrade,
    #[error("reply suite differs from the offered suite")]
    SuiteMismatch,
    #[error("malformed handshake message")]
    Malformed,
    #[error("X25519 share is not contributory")]
    WeakShare,
    #[error("transcript signature: {0}")]
    Signature(SigError),
    #[error("AEAD open failed")]
    Aead,
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS randomness");
    b
}

fn suite_at(b: &mut &[u8]) -> Result<CryptoSuiteId, KexError> {
    let code = u16::from_le_bytes(take(b, 2).ok_or(KexError::Malformed)?.try_into().unwrap());
    CryptoSuiteId::from_code(code).ok_or(KexError::Malformed)
}

fn x25519_at(b: &mut &[u8]) -> Result<XPub, KexError> {
    let x: [u8; 32] = take(b, 32).ok_or(KexError::Malformed)?.try_into().unwrap();
    Ok(XPub::from(x))
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn take_bytes<'a>(b: &mut &'a [u8]) -> Result<&'a [u8], KexError> {
    let n = u32::from_le_bytes(take(b, 4).ok_or(KexError::Malformed)?.try_into().unwrap()) as usize;
    take(b, n).ok_or(KexError::Malformed)
}

fn x25519_shared(sk: &StaticSecret, pk: &XPub) -> Result<[u8; 32], KexError> {
    let ss = sk.diffie_hellman(pk);
    if !ss.was_contributory() {
        return Err(KexError::WeakShare);
    }
    Ok(ss.to_bytes())
}

fn derive(th1: &[u8; 32], ss_x: &[u8; 32], ss_k: Option<&[u8]>, client: bool) -> Session {
    let mut ikm = ss_x.to_vec();
    if let Some(k) = ss_k {
        ikm.extend_from_slice(k);
    }
    let hk = Hkdf::<Sha256>::new(Some(th1), &ikm);
    let key = |info: &[u8]| {
        let mut k = [0u8; 32];
        hk.expand(info, &mut k).expect("32 bytes");
        Half {
            aead: XChaCha20Poly1305::new(&k.into()),
            ctr: 0,
        }
    };
    let (c2s, s2c) = (key(b"plx/kex/v1/c2s"), key(b"plx/kex/v1/s2c"));
    let (send, recv) = if client { (c2s, s2c) } else { (s2c, c2s) };
    Session { send, recv }
}

/// Initiator state between `hello` and the reply.
pub struct ClientHandshake {
    suite: CryptoSuiteId,
    x_sk: StaticSecret,
    kem_dk: Option<ml_kem::DecapsulationKey<MlKem768>>,
    hello: Vec<u8>,
}

impl ClientHandshake {
    /// Offer `suite`. Returns the state and the hello to send.
    pub fn start(suite: CryptoSuiteId) -> (Self, Vec<u8>) {
        let x_sk = StaticSecret::from(rand32());
        let mut hello = KEX_DOMAIN.to_vec();
        hello.extend_from_slice(&suite.code().to_le_bytes());
        hello.extend_from_slice(XPub::from(&x_sk).as_bytes());
        let kem_dk = suite.has_pq_components().then(|| {
            let mut seed = [0u8; 64];
            seed[..32].copy_from_slice(&rand32());
            seed[32..].copy_from_slice(&rand32());
            ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed.into())
        });
        put_opt(&mut hello, &kem_dk.as_ref().map(|dk| dk.encapsulation_key().to_bytes().to_vec()));
        let out = hello.clone();
        (Self { suite, x_sk, kem_dk, hello }, out)
    }

    /// Check the reply and sign the transcript. Returns the session, the
    /// finish message and the responder's key (the caller checks membership).
    pub fn finish(
        self,
        policy: SuitePolicy,
        key: &SuiteSigningKey,
        reply: &[u8],
    ) -> Result<(Session, Vec<u8>, SuitePublicKey), KexError> {
        let mut b = reply;
        if suite_at(&mut b)? != self.suite {
            return Err(KexError::SuiteMismatch);
        }
        let x_s = x25519_at(&mut b)?;
        let ct = take_opt(&mut b, MLKEM768_CT_BYTES).ok_or(KexError::Malformed)?;
        let pk_s = SuitePublicKey::decode(take_bytes(&mut b)?).ok_or(KexError::Malformed)?;
        let body_len = reply.len() - b.len();
        let sig_s = SuiteSignature::decode(take_bytes(&mut b)?).ok_or(KexError::Malformed)?;
        if !b.is_empty() || ct.is_some() != self.kem_dk.is_some() {
            return Err(KexError::Malformed);
        }
        let th1: [u8; 32] = Sha256::new()
            .chain_update(&self.hello)
            .chain_update(&reply[..body_len])
            .finalize()
            .into();
        verify(policy, &pk_s, CTX_SERVER, &th1, &sig_s).map_err(KexError::Signature)?;
        let ss_x = x25519_shared(&self.x_sk, &x_s)?;
        let ss_k = match (&self.kem_dk, ct) {
            (Some(dk), Some(ct)) => {
                let ct = ml_kem::Ciphertext::<MlKem768>::try_from(ct.as_slice()).map_err(|_| KexError::Malformed)?;
                Some(dk.decapsulate(&ct).to_vec())
            }
            _ => None,
        };
        let session = derive(&th1, &ss_x, ss_k.as_deref(), true);
        let th2 = transcript2(&th1, &sig_s);
        let pk_c = key.public().encode();
        let mut finish = Vec::new();
        put_bytes(&mut finish, &pk_c);
        put_bytes(&mut finish, &key.sign(CTX_CLIENT, &[&th2[..], &pk_c].concat()).encode());
        Ok((session, finish, pk_s))
    }
}

fn transcript2(th1: &[u8; 32], sig_s: &SuiteSignature) -> [u8; 32] {
    Sha256::new().chain_update(th1).chain_update(sig_s.encode()).finalize().into()
}

/// Responder state between its reply and the initiator's finish.
pub struct ServerHandshake {
    policy: SuitePolicy,
    th2: [u8; 32],
    session: Session,
}

/// Answer a hello. Rejects suites below `policy`.
pub fn respond(policy: SuitePolicy, key: &SuiteSigningKey, hello: &[u8]) -> Result<(ServerHandshake, Vec<u8>), KexError> {
    let mut b = hello;
    if take(&mut b, KEX_DOMAIN.len()) != Some(KEX_DOMAIN) {
        return Err(KexError::Malformed);
    }
    let suite = suite_at(&mut b)?;
    if suite < policy.min {
        return Err(KexError::Downgrade);
    }
    let x_c = x25519_at(&mut b)?;
    let ek = take_opt(&mut b, MLKEM768_EK_BYTES).ok_or(KexError::Malformed)?;
    if !b.is_empty() || ek.is_some() != suite.has_pq_components() {
        return Err(KexError::Malformed);
    }
    let x_sk = StaticSecret::from(rand32());
    let ss_x = x25519_shared(&x_sk, &x_c)?;
    let (ct, ss_k) = match ek {
        Some(ek) => {
            let ek = EncapsulationKey::<MlKem768>::new_from_slice(&ek).map_err(|_| KexError::Malformed)?;
            // `m` from the OS RNG (the crate's own RNG path needs rand_core 0.10).
            let (ct, ss) = ek.encapsulate_deterministic(&rand32().into());
            (Some(ct.to_vec()), Some(ss.to_vec()))
        }
        None => (None, None),
    };
    let mut reply = suite.code().to_le_bytes().to_vec();
    reply.extend_from_slice(XPub::from(&x_sk).as_bytes());
    put_opt(&mut reply, &ct);
    put_bytes(&mut reply, &key.public().encode());
    let th1: [u8; 32] = Sha256::new().chain_update(hello).chain_update(&reply).finalize().into();
    let sig_s = key.sign(CTX_SERVER, &th1);
    put_bytes(&mut reply, &sig_s.encode());
    let session = derive(&th1, &ss_x, ss_k.as_deref(), false);
    Ok((
        ServerHandshake {
            policy,
            th2: transcript2(&th1, &sig_s),
            session,
        },
        reply,
    ))
}

impl ServerHandshake {
    /// Verify the initiator's transcript signature. Returns the session and
    /// the initiator's key (the caller checks membership).
    pub fn finish(self, finish: &[u8]) -> Result<(Session, SuitePublicKey), KexError> {
        let mut b = finish;
        let pk_bytes = take_bytes(&mut b)?;
        let pk_c = SuitePublicKey::decode(pk_bytes).ok_or(KexError::Malformed)?;
        let sig_c = SuiteSignature::decode(take_bytes(&mut b)?).ok_or(KexError::Malformed)?;
        if !b.is_empty() {
            return Err(KexError::Malformed);
        }
        verify(self.policy, &pk_c, CTX_CLIENT, &[&self.th2[..], pk_bytes].concat(), &sig_c)
            .map_err(KexError::Signature)?;
        Ok((self.session, pk_c))
    }
}

/// One direction of a session: XChaCha20-Poly1305 with a counter nonce. TCP
/// delivers in order, so a dropped, replayed or reordered frame fails to open.
pub struct Half {
    aead: XChaCha20Poly1305,
    ctr: u64,
}

impl Half {
    fn nonce(&mut self) -> XNonce {
        let mut n = [0u8; 24];
        n[..8].copy_from_slice(&self.ctr.to_le_bytes());
        self.ctr += 1;
        n.into()
    }

    pub fn seal(&mut self, msg: &[u8]) -> Vec<u8> {
        let n = self.nonce();
        self.aead.encrypt(&n, Payload { msg, aad: KEX_DOMAIN }).expect("seal")
    }

    pub fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, KexError> {
        let n = self.nonce();
        self.aead
            .decrypt(&n, Payload { msg: ct, aad: KEX_DOMAIN })
            .map_err(|_| KexError::Aead)
    }
}

pub struct Session {
    pub send: Half,
    pub recv: Half,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(suite: CryptoSuiteId, b: u8) -> SuiteSigningKey {
        SuiteSigningKey::from_seed(suite, [b; 32])
    }

    fn run(
        offer: CryptoSuiteId,
        c_policy: SuitePolicy,
        s_policy: SuitePolicy,
        ck: &SuiteSigningKey,
        sk: &SuiteSigningKey,
    ) -> Result<(Session, Session), KexError> {
        let (c, hello) = ClientHandshake::start(offer);
        let (s, reply) = respond(s_policy, sk, &hello)?;
        let (cs, fin, pk_s) = c.finish(c_policy, ck, &reply)?;
        assert_eq!(pk_s, sk.public());
        let (ss, pk_c) = s.finish(&fin)?;
        assert_eq!(pk_c, ck.public());
        Ok((cs, ss))
    }

    #[test]
    fn hybrid_and_classical_sessions_carry_frames() {
        use CryptoSuiteId::*;
        for (suite, policy) in [(ClassicalV0, SuitePolicy::CLASSICAL), (HybridV1, SuitePolicy::HYBRID)] {
            let (ck, sk) = (key(suite, 1), key(suite, 2));
            let (mut c, mut s) = run(suite, policy, policy, &ck, &sk).unwrap();
            for i in 0..3u8 {
                let ct = c.send.seal(&[i; 100]);
                assert_eq!(ct.len(), 100 + TAG_BYTES);
                assert_eq!(s.recv.open(&ct).unwrap(), vec![i; 100]);
            }
            let back = s.send.seal(b"ack");
            assert_eq!(c.recv.open(&back).unwrap(), b"ack");
        }
    }

    #[test]
    fn hybrid_responder_rejects_classical_offer() {
        let (ck, sk) = (key(CryptoSuiteId::ClassicalV0, 1), key(CryptoSuiteId::HybridV1, 2));
        let r = run(CryptoSuiteId::ClassicalV0, SuitePolicy::CLASSICAL, SuitePolicy::HYBRID, &ck, &sk);
        assert!(matches!(r, Err(KexError::Downgrade)));
    }

    /// A man in the middle rewrites a hybrid offer into a classical one
    /// (dropping the ML-KEM key) toward a responder that still accepts
    /// classical. The responder's signature covers the rewritten hello, so the
    /// initiator refuses: first on the suite, and with the suite forged back,
    /// on the transcript signature.
    #[test]
    fn stripping_mlkem_from_the_offer_is_detected() {
        let (ck, sk) = (key(CryptoSuiteId::HybridV1, 1), key(CryptoSuiteId::HybridV1, 2));
        let (c, hello) = ClientHandshake::start(CryptoSuiteId::HybridV1);
        let mut forged = KEX_DOMAIN.to_vec();
        forged.extend_from_slice(&CryptoSuiteId::ClassicalV0.code().to_le_bytes());
        forged.extend_from_slice(&hello[KEX_DOMAIN.len() + 2..KEX_DOMAIN.len() + 34]);
        forged.extend_from_slice(&0u32.to_le_bytes());
        let (_, reply) = respond(SuitePolicy::CLASSICAL, &sk, &forged).unwrap();
        assert!(matches!(
            c.finish(SuitePolicy::CLASSICAL, &ck, &reply),
            Err(KexError::SuiteMismatch)
        ));

        // Same attack, relabelling the reply as hybrid: the signature fails.
        let (c, hello) = ClientHandshake::start(CryptoSuiteId::HybridV1);
        let mut forged = KEX_DOMAIN.to_vec();
        forged.extend_from_slice(&CryptoSuiteId::ClassicalV0.code().to_le_bytes());
        forged.extend_from_slice(&hello[KEX_DOMAIN.len() + 2..KEX_DOMAIN.len() + 34]);
        forged.extend_from_slice(&0u32.to_le_bytes());
        let (_, mut reply) = respond(SuitePolicy::CLASSICAL, &sk, &forged).unwrap();
        reply[..2].copy_from_slice(&CryptoSuiteId::HybridV1.code().to_le_bytes());
        // Reply has no ciphertext while the offer had a KEM key: malformed
        // before the signature is even checked. Either way: no session.
        assert!(c.finish(SuitePolicy::CLASSICAL, &ck, &reply).is_err());
    }

    #[test]
    fn classical_responder_key_rejected_by_hybrid_initiator() {
        let (ck, sk) = (key(CryptoSuiteId::HybridV1, 1), key(CryptoSuiteId::ClassicalV0, 2));
        let r = run(CryptoSuiteId::HybridV1, SuitePolicy::HYBRID, SuitePolicy::CLASSICAL, &ck, &sk);
        assert!(matches!(r, Err(KexError::Signature(SigError::Downgrade))));
    }

    #[test]
    fn tampered_transcript_and_frames_rejected() {
        let k = key(CryptoSuiteId::HybridV1, 3);
        let (c, hello) = ClientHandshake::start(CryptoSuiteId::HybridV1);
        let (_, mut reply) = respond(SuitePolicy::HYBRID, &k, &hello).unwrap();
        reply[2 + 5] ^= 1; // the responder's X25519 share
        assert!(matches!(c.finish(SuitePolicy::HYBRID, &k, &reply), Err(KexError::Signature(_))));

        // Finish signed by someone else for this transcript.
        let (c, hello) = ClientHandshake::start(CryptoSuiteId::HybridV1);
        let (s, reply) = respond(SuitePolicy::HYBRID, &k, &hello).unwrap();
        c.finish(SuitePolicy::HYBRID, &k, &reply).unwrap();
        let (c2, hello2) = ClientHandshake::start(CryptoSuiteId::HybridV1);
        let (_, reply2) = respond(SuitePolicy::HYBRID, &k, &hello2).unwrap();
        let (_, fin2, _) = c2.finish(SuitePolicy::HYBRID, &k, &reply2).unwrap();
        assert!(matches!(s.finish(&fin2), Err(KexError::Signature(_))));

        let (mut c, mut s) = run(CryptoSuiteId::HybridV1, SuitePolicy::HYBRID, SuitePolicy::HYBRID, &k, &k).unwrap();
        let mut ct = c.send.seal(b"intent");
        ct[0] ^= 1;
        assert_eq!(s.recv.open(&ct), Err(KexError::Aead));
        // Replay / reorder: frame 1 sealed, frame 2 sealed, open 2 first.
        let (mut c, mut s) = run(CryptoSuiteId::HybridV1, SuitePolicy::HYBRID, SuitePolicy::HYBRID, &k, &k).unwrap();
        let _a = c.send.seal(b"a");
        let b = c.send.seal(b"b");
        assert_eq!(s.recv.open(&b), Err(KexError::Aead));
    }

    /// `cargo test -p crypto-suite --release -- --ignored --nocapture kex_timing`
    #[test]
    #[ignore]
    fn kex_timing() {
        use std::time::Instant;
        for suite in [CryptoSuiteId::ClassicalV0, CryptoSuiteId::HybridV1] {
            let policy = SuitePolicy { min: suite };
            let (ck, sk) = (key(suite, 1), key(suite, 2));
            let n = 200;
            let (mut h_b, mut r_b, mut f_b) = (0, 0, 0);
            let t = Instant::now();
            for _ in 0..n {
                let (c, hello) = ClientHandshake::start(suite);
                let (s, reply) = respond(policy, &sk, &hello).unwrap();
                let (_, fin, _) = c.finish(policy, &ck, &reply).unwrap();
                s.finish(&fin).unwrap();
                (h_b, r_b, f_b) = (hello.len(), reply.len(), fin.len());
            }
            let per = t.elapsed().as_secs_f64() * 1e6 / n as f64;
            let (mut c, mut s) = run(suite, policy, policy, &ck, &sk).unwrap();
            let msg = vec![0u8; 100];
            let m = 100_000;
            let t = Instant::now();
            for _ in 0..m {
                let ct = c.send.seal(&msg);
                s.recv.open(&ct).unwrap();
            }
            let frame = t.elapsed().as_secs_f64() * 1e9 / m as f64;
            println!(
                "{suite:?}: handshake {per:.0} µs (both sides, one thread); hello {h_b} B, reply {r_b} B, finish {f_b} B, total {} B; 100 B frame seal+open {frame:.0} ns, +{TAG_BYTES} B",
                h_b + r_b + f_b
            );
        }
    }
}
