//! Public-tier sampling at n≫4 (Q-DA-6).
//!
//! [`HeightStatement`] (178 B) is [`AvailabilityKind::FullDownload`]. Larger
//! uncoded transcripts are chunk-Merkle sampled across a stripe ([`StripedNet`]).
//! Reconstructability is [`crate::Rs2d`], not this stripe. Not KZG, not a DA chain.

use std::collections::BTreeMap;

use commitments::{
    blob_root, chunk_digest, merkle_verify, sample_indices, sample_indices_hidden, Digest,
    MerkleProof, MerkleTree, CHUNK_BYTES,
};

pub use commitments::{DEFAULT_SAMPLES, FULL_DOWNLOAD_MAX};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvailabilityKind {
    FullDownload {
        bytes: usize,
    },
    Sampled {
        chunks: usize,
        samples: usize,
        chunk_bytes: usize,
    },
}

pub fn kind_for(len: usize) -> AvailabilityKind {
    if len <= FULL_DOWNLOAD_MAX {
        AvailabilityKind::FullDownload { bytes: len }
    } else {
        let chunks = len.div_ceil(CHUNK_BYTES);
        AvailabilityKind::Sampled {
            chunks,
            samples: DEFAULT_SAMPLES.min(chunks),
            chunk_bytes: CHUNK_BYTES,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChunkedBlob {
    pub bytes_len: usize,
    pub root: Digest,
    pub merkle: Digest,
    chunks: Vec<Vec<u8>>,
    tree: MerkleTree,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkOpening {
    pub index: usize,
    pub chunk: Vec<u8>,
    pub proof: MerkleProof,
}

impl ChunkedBlob {
    pub fn encode(bytes: &[u8]) -> Self {
        let n = bytes.len().div_ceil(CHUNK_BYTES).max(1);
        let mut chunks = Vec::with_capacity(n);
        let mut leaves = Vec::with_capacity(n);
        for i in 0..n {
            let start = i * CHUNK_BYTES;
            let end = (start + CHUNK_BYTES).min(bytes.len());
            let mut chunk = vec![0u8; CHUNK_BYTES];
            if start < bytes.len() {
                chunk[..end - start].copy_from_slice(&bytes[start..end]);
            }
            leaves.push(chunk_digest(&chunk));
            chunks.push(chunk);
        }
        let tree = MerkleTree::from_leaves(&leaves);
        let merkle = tree.root();
        let root = blob_root(bytes.len() as u64, CHUNK_BYTES as u32, merkle);
        Self {
            bytes_len: bytes.len(),
            root,
            merkle,
            chunks,
            tree,
        }
    }

    pub fn n_chunks(&self) -> usize {
        self.chunks.len()
    }

    pub fn sample_indices(&self, samples: usize) -> Vec<usize> {
        sample_indices(self.root, self.n_chunks(), samples)
    }

    pub fn sample_indices_hidden(&self, coins: &[u8; 32], samples: usize) -> Vec<usize> {
        sample_indices_hidden(coins, self.root, self.n_chunks(), samples)
    }

    pub fn open(&self, index: usize) -> ChunkOpening {
        ChunkOpening {
            index,
            chunk: self.chunks[index].clone(),
            proof: self.tree.open(index),
        }
    }

    pub fn verify_opening(&self, opening: &ChunkOpening) -> bool {
        verify_opening(self.merkle, self.n_chunks(), opening)
    }
}

pub fn verify_opening(merkle: Digest, n_chunks: usize, opening: &ChunkOpening) -> bool {
    opening.index < n_chunks
        && opening.chunk.len() == CHUNK_BYTES
        && merkle_verify(chunk_digest(&opening.chunk), &opening.proof, merkle)
}

/// Replica `r` stores chunks with `index % n == r`. Not RS. Not 2D.
#[derive(Clone, Debug)]
pub struct StripedNet {
    pub n: usize,
    pub blob: ChunkedBlob,
    shards: Vec<BTreeMap<usize, Vec<u8>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleError {
    MissingChunk,
    BadOpening,
}

impl StripedNet {
    pub fn disperse(bytes: &[u8], n: usize) -> Self {
        assert!(n > 0);
        let blob = ChunkedBlob::encode(bytes);
        let mut shards = vec![BTreeMap::new(); n];
        for i in 0..blob.n_chunks() {
            shards[i % n].insert(i, blob.chunks[i].clone());
        }
        Self { n, blob, shards }
    }

    pub fn withhold(&mut self, replica: usize) {
        self.shards[replica].clear();
    }

    pub fn fetch(&self, index: usize) -> Option<ChunkOpening> {
        let chunk = self.shards[index % self.n].get(&index)?.clone();
        Some(ChunkOpening {
            index,
            chunk,
            proof: self.blob.tree.open(index),
        })
    }

    /// Fetch and verify `samples` openings. Success is **not** reconstructability.
    pub fn light_sample(&self, samples: usize) -> Result<usize, SampleError> {
        self.light_sample_idx(&self.blob.sample_indices(samples))
    }

    pub fn light_sample_hidden(
        &self,
        coins: &[u8; 32],
        samples: usize,
    ) -> Result<usize, SampleError> {
        self.light_sample_idx(&self.blob.sample_indices_hidden(coins, samples))
    }

    fn light_sample_idx(&self, idx: &[usize]) -> Result<usize, SampleError> {
        let mut fetched = 0usize;
        for &i in idx {
            let opening = self.fetch(i).ok_or(SampleError::MissingChunk)?;
            if !self.blob.verify_opening(&opening) {
                return Err(SampleError::BadOpening);
            }
            fetched += opening.chunk.len() + opening.proof.siblings.len() * 32;
        }
        Ok(fetched)
    }
}
