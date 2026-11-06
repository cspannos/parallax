//! 2D Reed–Solomon over public chunks (Q-DA-6).
//!
//! Data sits in a `k×k` matrix of [`CHUNK_BYTES`] cells. Each row, then each
//! column, is extended to `n = 2k` with GF(256) RS (`reed-solomon-erasure`).
//! Light clients still sample 16 Merkle cells and **do not** reconstruct.
//! Recovery nodes reconstruct when every row/column has `k` shares.
//! Sample indices are a function of `blob_root`; 16 hits are not soundness.
//!
//! Not KZG. Not Groth16. Not a DA chain. Not a soundness proof of 16 samples.
//! [`HeightStatement`] (178 B) stays full-download.

use commitments::{
    blob_root, chunk_digest, sample_indices, sample_indices_hidden, Digest, MerkleTree, CHUNK_BYTES,
};
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::das::{verify_opening, ChunkOpening, SampleError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconstructError {
    NeedMoreShares,
    Rs,
    Length,
}

/// Smallest `k` with `k²` cells covering `len` bytes of 256-byte chunks.
pub fn data_k(len: usize) -> usize {
    let cells = len.div_ceil(CHUNK_BYTES).max(1);
    let mut k = 1usize;
    while k.saturating_mul(k) < cells {
        k += 1;
    }
    k
}

pub fn coded_n(k: usize) -> usize {
    k.saturating_mul(2)
}

fn codec(k: usize) -> ReedSolomon {
    ReedSolomon::new(k, k).expect("k data + k parity")
}

fn encode_line(rs: &ReedSolomon, data_k: usize, line: &[Vec<u8>]) -> Vec<Vec<u8>> {
    debug_assert_eq!(line.len(), data_k);
    let n = coded_n(data_k);
    let mut shards = Vec::with_capacity(n);
    shards.extend(line.iter().cloned());
    for _ in data_k..n {
        shards.push(vec![0u8; CHUNK_BYTES]);
    }
    rs.encode(&mut shards).expect("rs encode");
    shards
}

fn reconstruct_line(
    rs: &ReedSolomon,
    n: usize,
    k: usize,
    line: &mut [Option<Vec<u8>>],
) -> Result<bool, ReconstructError> {
    let known = line.iter().filter(|c| c.is_some()).count();
    if known < k {
        return Ok(false);
    }
    if known == n {
        return Ok(false);
    }
    rs.reconstruct(line).map_err(|_| ReconstructError::Rs)?;
    Ok(true)
}

#[derive(Clone, Debug)]
pub struct Rs2d {
    pub bytes_len: usize,
    pub k: usize,
    pub n: usize,
    pub root: Digest,
    pub merkle: Digest,
    cells: Vec<Option<Vec<u8>>>,
    tree: MerkleTree,
}

impl Rs2d {
    pub fn encode(bytes: &[u8]) -> Self {
        let k = data_k(bytes.len());
        let n = coded_n(k);
        let rs = codec(k);
        let mut data = vec![vec![0u8; CHUNK_BYTES]; k * k];
        for (i, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
            data[i][..chunk.len()].copy_from_slice(chunk);
        }
        let mut grid = vec![vec![0u8; CHUNK_BYTES]; n * n];
        for r in 0..k {
            let row: Vec<Vec<u8>> = (0..k).map(|c| data[r * k + c].clone()).collect();
            let encoded = encode_line(&rs, k, &row);
            for (c, shard) in encoded.into_iter().enumerate() {
                grid[r * n + c] = shard;
            }
        }
        for c in 0..n {
            let col: Vec<Vec<u8>> = (0..k).map(|r| grid[r * n + c].clone()).collect();
            let encoded = encode_line(&rs, k, &col);
            for (r, shard) in encoded.into_iter().enumerate() {
                grid[r * n + c] = shard;
            }
        }
        let leaves: Vec<Digest> = grid.iter().map(|c| chunk_digest(c)).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let merkle = tree.root();
        let root = blob_root(bytes.len() as u64, CHUNK_BYTES as u32, merkle);
        Self {
            bytes_len: bytes.len(),
            k,
            n,
            root,
            merkle,
            cells: grid.into_iter().map(Some).collect(),
            tree,
        }
    }

    pub fn n_cells(&self) -> usize {
        self.n * self.n
    }

    pub fn coded_bytes(&self) -> usize {
        self.n_cells() * CHUNK_BYTES
    }

    pub fn drop_cell(&mut self, r: usize, c: usize) {
        let i = r * self.n + c;
        self.cells[i] = None;
    }

    pub fn drop_row(&mut self, r: usize) {
        for c in 0..self.n {
            self.drop_cell(r, c);
        }
    }

    pub fn present(&self) -> usize {
        self.cells.iter().filter(|c| c.is_some()).count()
    }

    pub fn open(&self, index: usize) -> Option<ChunkOpening> {
        Some(ChunkOpening {
            index,
            chunk: self.cells.get(index)?.as_ref()?.clone(),
            proof: self.tree.open(index),
        })
    }

    pub fn verify_opening(&self, opening: &ChunkOpening) -> bool {
        verify_opening(self.merkle, self.n_cells(), opening)
    }

    pub fn sample_indices(&self, samples: usize) -> Vec<usize> {
        sample_indices(self.root, self.n_cells(), samples)
    }

    pub fn sample_indices_hidden(&self, coins: &[u8; 32], samples: usize) -> Vec<usize> {
        sample_indices_hidden(coins, self.root, self.n_cells(), samples)
    }

    /// Light-client path: 16 Merkle cells. Not reconstruction.
    pub fn light_sample(&self, samples: usize) -> Result<usize, SampleError> {
        self.light_sample_idx(&self.sample_indices(samples))
    }

    /// Client-local coins. Encoder who knows only `root` cannot precompute.
    /// Success is still not reconstructability.
    pub fn light_sample_hidden(
        &self,
        coins: &[u8; 32],
        samples: usize,
    ) -> Result<usize, SampleError> {
        self.light_sample_idx(&self.sample_indices_hidden(coins, samples))
    }

    fn light_sample_idx(&self, idx: &[usize]) -> Result<usize, SampleError> {
        let mut fetched = 0usize;
        for &i in idx {
            let opening = self.open(i).ok_or(SampleError::MissingChunk)?;
            if !self.verify_opening(&opening) {
                return Err(SampleError::BadOpening);
            }
            fetched += opening.chunk.len() + opening.proof.siblings.len() * 32;
        }
        Ok(fetched)
    }

    /// Recovery-node path. Needs `k` shares on a row or column, iterated.
    pub fn reconstruct(&mut self) -> Result<Vec<u8>, ReconstructError> {
        let rs = codec(self.k);
        let n = self.n;
        let k = self.k;
        loop {
            let mut progress = false;
            for r in 0..n {
                let mut line: Vec<Option<Vec<u8>>> =
                    (0..n).map(|c| self.cells[r * n + c].clone()).collect();
                if reconstruct_line(&rs, n, k, &mut line)? {
                    for c in 0..n {
                        let i = r * n + c;
                        self.cells[i] = line[c].clone();
                    }
                    progress = true;
                }
            }
            for c in 0..n {
                let mut line: Vec<Option<Vec<u8>>> =
                    (0..n).map(|r| self.cells[r * n + c].clone()).collect();
                if reconstruct_line(&rs, n, k, &mut line)? {
                    for r in 0..n {
                        let i = r * n + c;
                        self.cells[i] = line[r].clone();
                    }
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        let mut out = Vec::with_capacity(self.bytes_len);
        for r in 0..k {
            for c in 0..k {
                let cell = self.cells[r * n + c]
                    .as_ref()
                    .ok_or(ReconstructError::NeedMoreShares)?;
                out.extend_from_slice(cell);
            }
        }
        if out.len() < self.bytes_len {
            return Err(ReconstructError::Length);
        }
        out.truncate(self.bytes_len);
        Ok(out)
    }
}

/// Stripe coded cells across replicas. Not a DA chain.
#[derive(Clone, Debug)]
pub struct Rs2dNet {
    pub replicas: usize,
    pub grid: Rs2d,
}

impl Rs2dNet {
    pub fn disperse(bytes: &[u8], replicas: usize) -> Self {
        assert!(replicas > 0);
        Self {
            replicas,
            grid: Rs2d::encode(bytes),
        }
    }

    pub fn withhold_replica(&mut self, replica: usize) {
        let n_cells = self.grid.n_cells();
        for i in 0..n_cells {
            if i % self.replicas == replica {
                let r = i / self.grid.n;
                let c = i % self.grid.n;
                self.grid.drop_cell(r, c);
            }
        }
    }
}
