//! Chunk Merkle for public-tier sampling (Q-DA-6).
//!
//! Not treap [`node_digest`]. Not Poseidon2. Not 2D RS. Not a DA chain.
//! Public [`sample_indices`] are a function of `blob_root`. Hidden coins
//! ([`sample_indices_hidden`]) are not.

use super::Digest;

pub const DA_CHUNK_DOMAIN: &[u8] = b"plx/da/chunk/v1";
pub const DA_MERKLE_DOMAIN: &[u8] = b"plx/da/merkle/v1";
pub const DA_PAD_DOMAIN: &[u8] = b"plx/da/pad/v1";
pub const DA_BLOB_DOMAIN: &[u8] = b"plx/da/blob/v1";
pub const DA_SAMPLE_DOMAIN: &[u8] = b"plx/da/sample/v1";
/// Client-local coins. Not a function of `blob_root` alone.
pub const DA_HIDDEN_SAMPLE_DOMAIN: &[u8] = b"plx/da/sample/hidden/v1";

pub const CHUNK_BYTES: usize = 256;
pub const DEFAULT_SAMPLES: usize = 16;

/// `DEFAULT_SAMPLES * CHUNK_BYTES`. Blobs this small download whole.
pub const FULL_DOWNLOAD_MAX: usize = DEFAULT_SAMPLES * CHUNK_BYTES;

pub fn chunk_digest(chunk: &[u8]) -> Digest {
    Digest::from_bytes(chunk, DA_CHUNK_DOMAIN)
}

pub fn pad_digest() -> Digest {
    Digest::from_bytes(&[], DA_PAD_DOMAIN)
}

pub fn merkle_parent(left: Digest, right: Digest) -> Digest {
    let mut pair = [0u8; 64];
    pair[..32].copy_from_slice(&left.0);
    pair[32..].copy_from_slice(&right.0);
    Digest::from_bytes(&pair, DA_MERKLE_DOMAIN)
}

/// Binds payload length so zero-padding of the last chunk is not malleable.
pub fn blob_root(len: u64, chunk_bytes: u32, merkle: Digest) -> Digest {
    let mut buf = Vec::with_capacity(8 + 4 + 32);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&chunk_bytes.to_le_bytes());
    buf.extend_from_slice(&merkle.0);
    Digest::from_bytes(&buf, DA_BLOB_DOMAIN)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub index: usize,
    pub siblings: Vec<Digest>,
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    layers: Vec<Vec<Digest>>,
}

impl MerkleTree {
    pub fn from_leaves(leaves: &[Digest]) -> Self {
        Self {
            layers: build_layers(leaves),
        }
    }

    pub fn root(&self) -> Digest {
        *self
            .layers
            .last()
            .and_then(|l| l.first())
            .expect("non-empty tree")
    }

    pub fn open(&self, index: usize) -> MerkleProof {
        let mut idx = index;
        let mut siblings = Vec::new();
        for layer in &self.layers[..self.layers.len() - 1] {
            let sib = idx ^ 1;
            siblings.push(layer[sib]);
            idx /= 2;
        }
        MerkleProof { index, siblings }
    }
}

pub fn merkle_root(leaves: &[Digest]) -> Digest {
    MerkleTree::from_leaves(leaves).root()
}

pub fn merkle_open(leaves: &[Digest], index: usize) -> MerkleProof {
    MerkleTree::from_leaves(leaves).open(index)
}

pub fn merkle_verify(leaf: Digest, proof: &MerkleProof, root: Digest) -> bool {
    let mut h = leaf;
    let mut idx = proof.index;
    for sib in &proof.siblings {
        h = if idx % 2 == 0 {
            merkle_parent(h, *sib)
        } else {
            merkle_parent(*sib, h)
        };
        idx /= 2;
    }
    h == root && idx == 0
}

fn build_layers(leaves: &[Digest]) -> Vec<Vec<Digest>> {
    assert!(!leaves.is_empty());
    let width = leaves.len().next_power_of_two();
    let pad = pad_digest();
    let mut layer = Vec::with_capacity(width);
    layer.extend_from_slice(leaves);
    while layer.len() < width {
        layer.push(pad);
    }
    let mut layers = vec![layer];
    while layers.last().unwrap().len() > 1 {
        let prev = layers.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for pair in prev.chunks_exact(2) {
            next.push(merkle_parent(pair[0], pair[1]));
        }
        layers.push(next);
    }
    layers
}

pub fn sample_indices(root: Digest, n_chunks: usize, samples: usize) -> Vec<usize> {
    draw_indices(n_chunks, samples, |i| sample_raw(root, i, n_chunks))
}

/// Indices from client coins plus the blob root. The encoder who knows only
/// `root` cannot compute them. Openings still verify against the Merkle root.
/// Not reconstructability. Not a `2^{-40}` proof.
pub fn sample_indices_hidden(
    coins: &[u8; 32],
    root: Digest,
    n_chunks: usize,
    samples: usize,
) -> Vec<usize> {
    draw_indices(n_chunks, samples, |i| {
        sample_raw_hidden(coins, root, i, n_chunks)
    })
}

fn draw_indices(n_chunks: usize, samples: usize, mut draw: impl FnMut(u64) -> usize) -> Vec<usize> {
    assert!(n_chunks > 0);
    let want = samples.min(n_chunks);
    let mut seen = vec![false; n_chunks];
    let mut out = Vec::with_capacity(want);
    let mut i = 0u64;
    while out.len() < want && i < n_chunks as u64 * 8 {
        let idx = draw(i);
        i += 1;
        if !seen[idx] {
            seen[idx] = true;
            out.push(idx);
        }
    }
    if out.len() < want {
        for (idx, hit) in seen.iter().enumerate() {
            if !*hit {
                out.push(idx);
                if out.len() == want {
                    break;
                }
            }
        }
    }
    out
}

fn sample_raw(root: Digest, i: u64, n_chunks: usize) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DA_SAMPLE_DOMAIN);
    hasher.update(&root.0);
    hasher.update(&i.to_le_bytes());
    reduce_index(hasher.finalize(), n_chunks)
}

fn sample_raw_hidden(coins: &[u8; 32], root: Digest, i: u64, n_chunks: usize) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DA_HIDDEN_SAMPLE_DOMAIN);
    hasher.update(coins);
    hasher.update(&root.0);
    hasher.update(&i.to_le_bytes());
    reduce_index(hasher.finalize(), n_chunks)
}

fn reduce_index(out: blake3::Hash, n_chunks: usize) -> usize {
    let mut wide = [0u8; 8];
    wide.copy_from_slice(&out.as_bytes()[..8]);
    (u64::from_le_bytes(wide) % n_chunks as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_verify_roundtrip() {
        let leaves: Vec<Digest> = (0..5).map(|i| chunk_digest(&[i])).collect();
        let root = merkle_root(&leaves);
        for i in 0..leaves.len() {
            let proof = merkle_open(&leaves, i);
            assert!(merkle_verify(leaves[i], &proof, root));
            assert!(!merkle_verify(leaves[(i + 1) % leaves.len()], &proof, root));
        }
    }

    #[test]
    fn sample_indices_are_unique_and_in_range() {
        let root = chunk_digest(b"root");
        let idx = sample_indices(root, 20, 16);
        assert_eq!(idx.len(), 16);
        let mut sorted = idx.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 16);
        assert!(idx.iter().all(|&i| i < 20));
    }

    #[test]
    fn hidden_coins_are_not_the_public_fs_set() {
        let root = chunk_digest(b"root");
        let public = sample_indices(root, 1444, 16);
        let coins = [1u8; 32];
        let hidden = sample_indices_hidden(&coins, root, 1444, 16);
        assert_eq!(hidden.len(), 16);
        assert_ne!(public, hidden);
        let other = sample_indices_hidden(&[2u8; 32], root, 1444, 16);
        assert_ne!(hidden, other);
        let mut sorted = hidden.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 16);
    }

    #[test]
    fn blob_root_binds_length() {
        let m = merkle_root(&[chunk_digest(&[1])]);
        assert_ne!(blob_root(178, 256, m), blob_root(179, 256, m));
    }
}
