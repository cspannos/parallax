//! 2D RS reconstruct. 16 Merkle samples are not reconstruction. Not a DA chain.

use std::time::Instant;

use commitments::{CHUNK_BYTES, DEFAULT_SAMPLES, FULL_DOWNLOAD_MAX};
use proof_adapter::{
    coded_n, data_k, drop_complement, kind_for, AvailabilityKind, ReconstructError, Rs2d, Rs2dNet,
};

const TINY_F_PROD_BYTES: usize = 84_214;
const TAPE_PROOF_BYTES: usize = 1_291_000;

#[test]
fn statement_stays_full_download() {
    assert_eq!(kind_for(178), AvailabilityKind::FullDownload { bytes: 178 });
    assert!(178 <= FULL_DOWNLOAD_MAX);
}

#[test]
fn data_k_covers_payload() {
    assert_eq!(data_k(1), 1);
    assert_eq!(data_k(CHUNK_BYTES), 1);
    assert_eq!(data_k(CHUNK_BYTES + 1), 2);
    let k = data_k(TINY_F_PROD_BYTES);
    assert_eq!(k, 19);
    assert!(k * k * CHUNK_BYTES >= TINY_F_PROD_BYTES);
    assert_eq!(coded_n(k), 38);
}

#[test]
fn tape_size_class_is_four_times_data_square() {
    let k = data_k(TAPE_PROOF_BYTES);
    assert_eq!(k, 72);
    assert_eq!(coded_n(k) * coded_n(k) * CHUNK_BYTES, 5_308_416);
}

#[test]
fn tape_size_class_encodes_and_sixteen_do_not_reconstruct() {
    let t0 = Instant::now();
    let bytes = vec![7u8; TAPE_PROOF_BYTES];
    let mut g = Rs2d::encode(&bytes);
    let encode_ms = t0.elapsed().as_millis();
    assert_eq!(g.k, 72);
    assert_eq!(g.n, 144);
    assert_eq!(g.coded_bytes(), 5_308_416);
    let fetched = g.light_sample(DEFAULT_SAMPLES).unwrap();
    assert_eq!(fetched, 11_776);
    let idx = g.sample_indices(DEFAULT_SAMPLES);
    drop_complement(&mut g, &idx);
    assert_eq!(g.present(), DEFAULT_SAMPLES);
    assert_eq!(g.reconstruct(), Err(ReconstructError::NeedMoreShares));
    eprintln!(
        "2D RS tape k=72: encode {} ms, orig {} B, coded {} B, 16-sample {} B (not reconstruct)",
        encode_ms,
        TAPE_PROOF_BYTES,
        g.coded_bytes(),
        fetched
    );
}

#[test]
fn tape_size_class_missing_row_reconstructs() {
    let bytes = vec![5u8; TAPE_PROOF_BYTES];
    let mut g = Rs2d::encode(&bytes);
    g.drop_row(0);
    assert_eq!(g.reconstruct().unwrap(), bytes);
}

#[test]
fn roundtrip_and_missing_row() {
    let bytes: Vec<u8> = (0..8_000).map(|i| (i % 251) as u8).collect();
    let mut g = Rs2d::encode(&bytes);
    assert_eq!(g.k, 6);
    assert_eq!(g.n, 12);
    g.drop_row(0);
    assert_eq!(g.reconstruct().unwrap(), bytes);
}

#[test]
fn erasure_square_larger_than_k_fails() {
    let bytes = vec![3u8; 8_000];
    let mut g = Rs2d::encode(&bytes);
    let hole = g.k + 1;
    for r in 0..hole {
        for c in 0..hole {
            g.drop_cell(r, c);
        }
    }
    assert_eq!(g.reconstruct(), Err(ReconstructError::NeedMoreShares));
}

#[test]
fn sixteen_samples_do_not_reconstruct_tiny_f_size() {
    let bytes = vec![9u8; TINY_F_PROD_BYTES];
    let mut g = Rs2d::encode(&bytes);
    assert!(g.k > DEFAULT_SAMPLES);
    let idx = g.sample_indices(DEFAULT_SAMPLES);
    let keep: std::collections::BTreeSet<usize> = idx.iter().copied().collect();
    for i in 0..g.n_cells() {
        if !keep.contains(&i) {
            let r = i / g.n;
            let c = i % g.n;
            g.drop_cell(r, c);
        }
    }
    assert_eq!(g.present(), idx.len());
    assert_eq!(g.reconstruct(), Err(ReconstructError::NeedMoreShares));
}

#[test]
fn light_sample_is_not_reconstruct() {
    let bytes = vec![1u8; TINY_F_PROD_BYTES];
    let g = Rs2d::encode(&bytes);
    let fetched = g.light_sample(DEFAULT_SAMPLES).unwrap();
    assert!(fetched < bytes.len());
    assert!(fetched < g.coded_bytes());
    eprintln!(
        "2D RS tiny-F size: orig {} B, coded {} B (k={} n={}), sample {} B",
        bytes.len(),
        g.coded_bytes(),
        g.k,
        g.n,
        fetched
    );
}

#[test]
fn replica_withhold_still_reconstructs() {
    let bytes: Vec<u8> = (0..8_000).map(|i| (i % 199) as u8).collect();
    let mut net = Rs2dNet::disperse(&bytes, 4);
    net.withhold_replica(0);
    assert_eq!(net.grid.reconstruct().unwrap(), bytes);
}
