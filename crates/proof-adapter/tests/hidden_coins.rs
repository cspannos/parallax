//! Client-local sample coins (Q-DA-6).
//!
//! Public `sample_indices` are a function of `blob_root`. Hidden coins are
//! not. Complement withhold of the public 16 fools Fiat–Shamir and is caught
//! by a client who kept coins. 16 hidden hits still do not reconstruct.
//! 178 B full-downloads. Not KZG. Not `π`.

use commitments::DEFAULT_SAMPLES;
use proof_adapter::{
    drop_complement, kind_for, light_samples_all_present, light_samples_all_present_hidden,
    min_hidden_samples_to_reconstruct, AvailabilityKind, ReconstructError, Rs2d, SampleError,
};

const TINY_F_PROD_BYTES: usize = 84_214;
const TAPE_PROOF_BYTES: usize = 1_291_000;
const COINS: [u8; 32] = [1u8; 32];

fn tiny_f_grid() -> Rs2d {
    Rs2d::encode(&vec![9u8; TINY_F_PROD_BYTES])
}

fn tape_grid() -> Rs2d {
    Rs2d::encode(&vec![7u8; TAPE_PROOF_BYTES])
}

#[test]
fn statement_stays_full_download() {
    assert_eq!(kind_for(178), AvailabilityKind::FullDownload { bytes: 178 });
}

#[test]
fn hidden_coins_are_not_the_public_set() {
    let g = tiny_f_grid();
    let public = g.sample_indices(DEFAULT_SAMPLES);
    let hidden = g.sample_indices_hidden(&COINS, DEFAULT_SAMPLES);
    assert_eq!(public.len(), DEFAULT_SAMPLES);
    assert_eq!(hidden.len(), DEFAULT_SAMPLES);
    assert_ne!(public, hidden);
    eprintln!(
        "hidden-coins vs public FS: public={:?} hidden={:?}",
        public, hidden
    );
}

#[test]
fn public_complement_fools_fs_and_is_caught_by_hidden_coins() {
    let mut g = tiny_f_grid();
    let public = g.sample_indices(DEFAULT_SAMPLES);
    drop_complement(&mut g, &public);
    assert!(light_samples_all_present(&g, DEFAULT_SAMPLES));
    assert_eq!(
        g.light_sample_hidden(&COINS, DEFAULT_SAMPLES),
        Err(SampleError::MissingChunk)
    );
    assert!(!light_samples_all_present_hidden(
        &g,
        &COINS,
        DEFAULT_SAMPLES
    ));
    assert_eq!(g.reconstruct(), Err(ReconstructError::NeedMoreShares));
}

#[test]
fn sixteen_hidden_hits_still_do_not_reconstruct() {
    let mut g = tiny_f_grid();
    let hidden = g.sample_indices_hidden(&COINS, DEFAULT_SAMPLES);
    drop_complement(&mut g, &hidden);
    assert!(light_samples_all_present_hidden(
        &g,
        &COINS,
        DEFAULT_SAMPLES
    ));
    assert_eq!(g.reconstruct(), Err(ReconstructError::NeedMoreShares));
}

#[test]
fn hidden_samples_until_reconstruct_is_not_sixteen() {
    let g = tiny_f_grid();
    let s = min_hidden_samples_to_reconstruct(&g, &COINS);
    assert_eq!(s, 495);
    let mut kept = g.clone();
    let idx = kept.sample_indices_hidden(&COINS, s);
    drop_complement(&mut kept, &idx);
    assert_eq!(kept.reconstruct().unwrap().len(), TINY_F_PROD_BYTES);
    let mut fewer = g.clone();
    let idx = fewer.sample_indices_hidden(&COINS, s - 1);
    drop_complement(&mut fewer, &idx);
    assert_eq!(fewer.reconstruct(), Err(ReconstructError::NeedMoreShares));
    let fetched = g.light_sample_hidden(&COINS, s).unwrap();
    assert_eq!(fetched, 300_960);
    eprintln!(
        "hidden-coins reconstruct tiny-F: min samples={} fetched={} B (16 still do not; not 2^{{-40}})",
        s, fetched
    );
}

#[test]
fn full_grid_hidden_sample_succeeds_and_is_smaller_than_blob() {
    let g = tiny_f_grid();
    let fetched = g.light_sample_hidden(&COINS, DEFAULT_SAMPLES).unwrap();
    assert!(fetched < TINY_F_PROD_BYTES);
    assert!(fetched < g.coded_bytes());
    eprintln!(
        "hidden-coins tiny-F: coded {} B, hidden-sample {} B (16 cells, not reconstruct)",
        g.coded_bytes(),
        fetched
    );
}

/// Hidden reconstruct of tape `k=72`. Not `2^{-40}` (94). Not public 8621. Not `π`.
#[test]
fn hidden_samples_until_reconstruct_tape_is_not_ninety_four() {
    let t0 = std::time::Instant::now();
    let g = tape_grid();
    let s = min_hidden_samples_to_reconstruct(&g, &COINS);
    let search_ms = t0.elapsed().as_millis();
    assert_eq!(s, 8_421);
    let mut kept = g.clone();
    let idx = kept.sample_indices_hidden(&COINS, s);
    drop_complement(&mut kept, &idx);
    assert_eq!(kept.reconstruct().unwrap().len(), TAPE_PROOF_BYTES);
    let mut fewer = g.clone();
    let idx = fewer.sample_indices_hidden(&COINS, s - 1);
    drop_complement(&mut fewer, &idx);
    assert_eq!(fewer.reconstruct(), Err(ReconstructError::NeedMoreShares));
    let fetched = g.light_sample_hidden(&COINS, s).unwrap();
    assert_eq!(fetched, 6_197_856);
    assert!(fetched > g.coded_bytes());
    eprintln!(
        "hidden-coins reconstruct tape k=72: min samples={} fetched={} B > coded {} B search={} ms (94 is 2^{{-40}} vs square; public FS is 8621)",
        s,
        fetched,
        g.coded_bytes(),
        search_ms
    );
}
