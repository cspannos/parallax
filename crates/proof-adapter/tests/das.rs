//! Q-DA-6 remainder: chunk-Merkle sampling at n≫4. Not 2D RS. Not a DA chain.

use std::collections::BTreeSet;

use commitments::{CHUNK_BYTES, DEFAULT_SAMPLES, FULL_DOWNLOAD_MAX};
use proof_adapter::{kind_for, AvailabilityKind, SampleError, StripedNet};
use protocol_types::CanonicalEncode;

const TINY_F_PROD_BYTES: usize = 84_214;
const TAPE_PROOF_BYTES: usize = 1_291_000;

#[test]
fn height_statement_is_full_download() {
    assert_eq!(FULL_DOWNLOAD_MAX, DEFAULT_SAMPLES * CHUNK_BYTES);
    assert_eq!(FULL_DOWNLOAD_MAX, 4096);
    assert!(178 <= FULL_DOWNLOAD_MAX);
    assert_eq!(kind_for(178), AvailabilityKind::FullDownload { bytes: 178 });
}

#[test]
fn breakeven_is_full_download_max() {
    assert_eq!(
        kind_for(FULL_DOWNLOAD_MAX),
        AvailabilityKind::FullDownload {
            bytes: FULL_DOWNLOAD_MAX
        }
    );
    match kind_for(FULL_DOWNLOAD_MAX + 1) {
        AvailabilityKind::Sampled {
            chunks, samples, ..
        } => {
            assert_eq!(chunks, 17);
            assert_eq!(samples, 16);
        }
        AvailabilityKind::FullDownload { .. } => panic!("4097 B samples"),
    }
}

#[test]
fn tiny_f_proof_size_is_sampled() {
    match kind_for(TINY_F_PROD_BYTES) {
        AvailabilityKind::Sampled {
            chunks,
            samples,
            chunk_bytes,
        } => {
            assert_eq!(chunk_bytes, 256);
            assert_eq!(samples, 16);
            assert_eq!(chunks, TINY_F_PROD_BYTES.div_ceil(256));
        }
        AvailabilityKind::FullDownload { .. } => panic!("84 KB must sample"),
    }
}

#[test]
fn n100_withhold_detected_when_sample_hits() {
    let mut net = StripedNet::disperse(&vec![7u8; TINY_F_PROD_BYTES], 100);
    let idx = net.blob.sample_indices(DEFAULT_SAMPLES);
    net.withhold(idx[0] % 100);
    assert_eq!(
        net.light_sample(DEFAULT_SAMPLES),
        Err(SampleError::MissingChunk)
    );
}

#[test]
fn n100_sample_can_miss_a_hole() {
    let mut net = StripedNet::disperse(&vec![7u8; TINY_F_PROD_BYTES], 100);
    let idx = net.blob.sample_indices(DEFAULT_SAMPLES);
    let hit: BTreeSet<usize> = idx.iter().map(|i| i % 100).collect();
    let miss = (0..100)
        .find(|r| !hit.contains(r))
        .expect("16 samples < 100 replicas");
    net.withhold(miss);
    assert!(
        net.light_sample(DEFAULT_SAMPLES).is_ok(),
        "sampling without RS can miss a withheld replica — not a security proof"
    );
}

#[test]
fn sample_bytes_vs_full_download() {
    for (label, len) in [
        ("tiny-F prod size", TINY_F_PROD_BYTES),
        ("8-event C' tape size class", TAPE_PROOF_BYTES),
    ] {
        let net = StripedNet::disperse(&vec![1u8; len], 100);
        let fetched = net.light_sample(DEFAULT_SAMPLES).unwrap();
        assert!(fetched < len);
        eprintln!(
            "DAS sample {label}: full {len} B, sample {fetched} B, chunks {}, n=100",
            net.blob.n_chunks()
        );
    }
}

#[test]
fn opening_does_not_verify_against_wrong_root() {
    let a = StripedNet::disperse(&vec![1u8; TINY_F_PROD_BYTES], 4);
    let b = StripedNet::disperse(&vec![2u8; TINY_F_PROD_BYTES], 4);
    let opening = a.blob.open(0);
    assert!(a.blob.verify_opening(&opening));
    assert!(!b.blob.verify_opening(&opening));
}

#[test]
fn statement_encode_stays_178() {
    use protocol_types::{Bytes32, ConsensusValue, Height, HeightStatement};
    let v = ConsensusValue {
        parent: ConsensusValue::GENESIS_PARENT,
        height: Height(1),
        state_root: Bytes32([1; 32]),
        input_commitment: Bytes32([2; 32]),
        settlement_commitment: Bytes32([3; 32]),
    };
    let stmt = HeightStatement::from_value(Bytes32([0xaa; 32]), &v);
    assert_eq!(stmt.encode_vec().len(), 178);
    assert_eq!(
        kind_for(stmt.encode_vec().len()),
        AvailabilityKind::FullDownload { bytes: 178 }
    );
}
