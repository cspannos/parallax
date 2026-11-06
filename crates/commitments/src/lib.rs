//! Domain-separated Blake3 commitments.
#![forbid(unsafe_code)]

//!
//! A commitment is a binding hash of canonical bytes. It is **not** a validity
//! proof of `S' = F(S, I)` (see ADR 0003).

use protocol_types::{
    Bytes32, CanonicalEncode, ConsensusValue, EncodeBuf, HeightStatement, ENCODING_VERSION,
};

pub const STATE_DOMAIN: &[u8] = b"plx/clob/state/v1";
pub const RECEIPT_DOMAIN: &[u8] = b"plx/clob/receipt/v1";
pub const INPUT_DOMAIN: &[u8] = b"plx/clob/input/v1";
pub const VALUE_ID_DOMAIN: &[u8] = b"plx/cons/value/v1";
pub const EVM_STATE_DOMAIN: &[u8] = b"plx/evm/state/v1";
pub const INC_DOMAIN: &[u8] = b"plx/clob/inc/v1";
/// Public-tier availability of [`HeightStatement`] (ADR 0005 / Q-DA-6).
/// Not DAS. Not a DA chain. Not `id(v)`.
pub const PUBLIC_DA_DOMAIN: &[u8] = b"plx/da/public/v1";
/// Domain of [`derive_order_id`] (ADR 0026; v2 = SHA-256, ADR 0032).
pub const ORDER_ID_DOMAIN: &[u8] = b"plx/clob/orderid/v2";

/// Production order id (ADR 0026): the first 16 bytes of
/// `SHA-256(digest_preimage(owner ‖ nonce_le, ORDER_ID_DOMAIN))`. Each
/// `(owner, nonce)` pair is consumed at most once, so ids are unique forever
/// without a seen set, and cannot be squatted by another owner. SHA-256 since
/// ADR 0032: one per Place, and zkVM guests accelerate it (BLAKE3 was ~3.6 K
/// cycles each in software). Only production engines derive ids; `C'` v1
/// keeps client ids, so no v1 circuit depends on this.
pub fn derive_order_id(owner: &protocol_types::OwnerId, nonce: u64) -> protocol_types::OrderId {
    let mut b = [0u8; 40];
    b[..32].copy_from_slice(&owner.0);
    b[32..].copy_from_slice(&nonce.to_le_bytes());
    let d = hashed_map::sha256_once(&digest_preimage(&b, ORDER_ID_DOMAIN));
    protocol_types::OrderId(d[..16].try_into().expect("16 of 32 bytes"))
}

mod das_merkle;
mod hashed_map;
mod inc_tape;
mod treap_witness;

pub use das_merkle::{
    blob_root, chunk_digest, merkle_open, merkle_root, merkle_verify, pad_digest, sample_indices,
    sample_indices_hidden, MerkleProof, MerkleTree, CHUNK_BYTES, DA_BLOB_DOMAIN, DA_CHUNK_DOMAIN,
    DA_HIDDEN_SAMPLE_DOMAIN, DA_MERKLE_DOMAIN, DA_PAD_DOMAIN, DA_SAMPLE_DOMAIN, DEFAULT_SAMPLES,
    FULL_DOWNLOAD_MAX,
};

pub use hashed_map::{
    encode_bytes, prio_preimage, priority_u64, priority_u64_with, set_sha256_impl,
    start_c_prime_trace, start_node_digest_trace,
    start_prio_trace, take_c_prime_trace, take_node_digest_trace, take_prio_trace,
    take_treap_hash_calls, treap_empty_digest, treap_empty_digest_with, treap_node_digest,
    treap_node_hash_with, HashedMap, NodeDigestOpening,
    TreapHash, TreapHashCalls, TREAP_EMPTY_DOMAIN, TREAP_NODE_DOMAIN, TREAP_PRIO_DOMAIN,
};
pub use inc_tape::{
    inc_root, inc_root_preimage, inc_root_with, IncHeader, IncTape, TapeClaim, TapeError, INC_OPS_DOMAIN, MAP_NONCES, MAP_RESTING,
    MAP_SEEN,
};
pub use treap_witness::{StepRoots, TreapOp, TreapStep, WitnessError, WitnessNode};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 32]);

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Concatenation hashed by [`Digest::from_bytes`]: domain || version || len || bytes.
pub fn digest_preimage(bytes: &[u8], domain: &[u8]) -> Vec<u8> {
    let mut pre = Vec::with_capacity(domain.len() + 2 + 8 + bytes.len());
    pre.extend_from_slice(domain);
    pre.extend_from_slice(&ENCODING_VERSION.to_le_bytes());
    pre.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    pre.extend_from_slice(bytes);
    pre
}

/// `u32` count || items. Payload of [`Digest::from_bytes`] for a committed list.
pub fn commit_list_payload<T: CanonicalEncode>(items: &[T]) -> Vec<u8> {
    let mut buf = EncodeBuf::new();
    buf.u32(items.len() as u32);
    for item in items {
        item.encode(&mut buf);
    }
    buf.into_vec()
}

impl Digest {
    pub fn from_bytes(bytes: &[u8], domain: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&ENCODING_VERSION.to_le_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn encode_tagged(value: &impl CanonicalEncode, domain: &[u8]) -> Self {
        let mut buf = EncodeBuf::new();
        value.encode(&mut buf);
        Self::from_bytes(buf.as_slice(), domain)
    }

    pub fn from_bytes32(bytes: Bytes32) -> Self {
        Self(bytes.0)
    }

    pub fn to_bytes32(self) -> Bytes32 {
        Bytes32(self.0)
    }
}

impl CanonicalEncode for Digest {
    fn encode(&self, buf: &mut EncodeBuf) {
        buf.bytes(&self.0);
    }
}

pub type StateRoot = Digest;

/// `id(v)` for an M4a [`ConsensusValue`] (ADR 0009).
pub fn value_id(value: &ConsensusValue) -> Digest {
    Digest::encode_tagged(value, VALUE_ID_DOMAIN)
}

/// Binding id of the public DA blob (the [`HeightStatement`] bytes).
/// Carries `C` (`pre_root`), which [`value_id`] does not.
pub fn public_statement_id(stmt: &HeightStatement) -> Digest {
    Digest::encode_tagged(stmt, PUBLIC_DA_DOMAIN)
}

/// Incremental hasher for canonical state walks. Callers must visit in the
/// documented order; the hasher does not sort.
pub struct StateHasher {
    inner: blake3::Hasher,
}

impl StateHasher {
    pub fn new() -> Self {
        Self::with_domain(STATE_DOMAIN)
    }

    pub fn with_domain(domain: &[u8]) -> Self {
        let mut inner = blake3::Hasher::new();
        inner.update(domain);
        inner.update(&ENCODING_VERSION.to_le_bytes());
        Self { inner }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.inner.update(&(bytes.len() as u64).to_le_bytes());
        self.inner.update(bytes);
    }

    pub fn write_encoded(&mut self, value: &impl CanonicalEncode) {
        let mut buf = EncodeBuf::new();
        value.encode(&mut buf);
        self.write(buf.as_slice());
    }

    pub fn tag(&mut self, tag: &[u8]) {
        self.inner.update(tag);
    }

    pub fn finalize(self) -> StateRoot {
        Digest(*self.inner.finalize().as_bytes())
    }
}

impl Default for StateHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation() {
        let a = Digest::from_bytes(b"abc", STATE_DOMAIN);
        let b = Digest::from_bytes(b"abc", RECEIPT_DOMAIN);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_preimage_is_from_bytes_msg() {
        let bytes = b"abc";
        let pre = digest_preimage(bytes, INPUT_DOMAIN);
        assert_eq!(
            Digest::from_bytes(bytes, INPUT_DOMAIN).0,
            *blake3::hash(&pre).as_bytes()
        );
    }

    #[test]
    fn value_id_is_not_a_state_root_hash() {
        let v = ConsensusValue {
            parent: ConsensusValue::GENESIS_PARENT,
            height: protocol_types::Height(1),
            state_root: Bytes32([1; 32]),
            input_commitment: Bytes32([2; 32]),
            settlement_commitment: Bytes32([3; 32]),
        };
        let id = value_id(&v);
        let as_state = Digest::from_bytes(&v.encode_vec(), STATE_DOMAIN);
        assert_ne!(id, as_state);
        assert_ne!(id.0, [0u8; 32]);
    }

    #[test]
    fn public_statement_id_is_not_value_id() {
        let v = ConsensusValue {
            parent: ConsensusValue::GENESIS_PARENT,
            height: protocol_types::Height(1),
            state_root: Bytes32([1; 32]),
            input_commitment: Bytes32([2; 32]),
            settlement_commitment: Bytes32([3; 32]),
        };
        let stmt = HeightStatement::from_value(Bytes32([0xaa; 32]), &v);
        let pid = public_statement_id(&stmt);
        assert_ne!(pid, value_id(&v));
        assert_ne!(pid, Digest::encode_tagged(&stmt, VALUE_ID_DOMAIN));
        assert_eq!(stmt.encode_vec().len(), 178);
    }
}
