//! Crypto agility on the wire (Phase 7, ADR 0030). Algorithms are named, not
//! assumed: keys and signatures carry a [`CryptoSuiteId`], and signed bytes
//! include it, so a signature cannot be replayed under another suite.

use crate::codec::{CanonicalEncode, EncodeBuf};
use crate::decode::{CanonicalDecode, DecodeBuf, DecodeError};

/// One primitive. Codes are stable wire values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum AlgorithmId {
    Ed25519 = 0x0101,
    /// FIPS 204, parameter set 65.
    MlDsa65 = 0x0201,
    X25519 = 0x0301,
    /// FIPS 203, parameter set 768.
    MlKem768 = 0x0401,
    XChaCha20Poly1305 = 0x0501,
    Sha256 = 0x0601,
    Blake3 = 0x0602,
}

/// A bundle of primitives used together. Ordered by strength: a policy names
/// the minimum suite it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum CryptoSuiteId {
    /// Phase 0 (`post-quantum.md`): Ed25519 signatures, X25519 key exchange.
    ClassicalV0 = 0x0000,
    /// Phase 1: Ed25519 **and** ML-DSA-65 signatures (both must verify);
    /// X25519 **and** ML-KEM-768 key exchange (both feed the key).
    HybridV1 = 0x0001,
}

impl CryptoSuiteId {
    pub fn code(self) -> u16 {
        self as u16
    }

    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0000 => Some(Self::ClassicalV0),
            0x0001 => Some(Self::HybridV1),
            _ => None,
        }
    }

    /// Signature algorithms; a signature carries one component per entry.
    pub fn signature_algorithms(self) -> &'static [AlgorithmId] {
        match self {
            Self::ClassicalV0 => &[AlgorithmId::Ed25519],
            Self::HybridV1 => &[AlgorithmId::Ed25519, AlgorithmId::MlDsa65],
        }
    }

    /// Key-establishment algorithms; each contributes to the session key.
    pub fn kex_algorithms(self) -> &'static [AlgorithmId] {
        match self {
            Self::ClassicalV0 => &[AlgorithmId::X25519],
            Self::HybridV1 => &[AlgorithmId::X25519, AlgorithmId::MlKem768],
        }
    }

    /// True if this suite has a post-quantum component for signatures and
    /// key establishment. Not a claim that the network is PQ secure.
    pub fn has_pq_components(self) -> bool {
        matches!(self, Self::HybridV1)
    }
}

impl CanonicalEncode for CryptoSuiteId {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.u16(self.code());
    }
}

impl CanonicalDecode for CryptoSuiteId {
    fn decode(buf: &mut DecodeBuf<'_>) -> Result<Self, DecodeError> {
        Self::from_code(buf.u16()?).ok_or(DecodeError::UnknownTag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_codes_round_trip_and_unknown_is_rejected() {
        for s in [CryptoSuiteId::ClassicalV0, CryptoSuiteId::HybridV1] {
            assert_eq!(CryptoSuiteId::decode_slice(&s.encode_vec()), Ok(s));
        }
        assert!(CryptoSuiteId::decode_slice(&7u16.to_le_bytes()).is_err());
        assert!(CryptoSuiteId::ClassicalV0 < CryptoSuiteId::HybridV1);
    }
}
