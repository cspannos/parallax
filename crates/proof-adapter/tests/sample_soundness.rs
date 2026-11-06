//! Sample-soundness of 16 public Merkle hits (Q-DA-6).
//!
//! Indices come from `blob_root`. The encoder knows them. 16 hits are not a
//! proof that the network can reconstruct. Not KZG. Not `π`.

use commitments::{DEFAULT_SAMPLES, FULL_DOWNLOAD_MAX};
use proof_adapter::{
    avoiding_squares, cheaper_hidden_recovery, cheaper_public_recovery, drop_complement,
    drop_unreconstructable_square_avoiding, kind_for, light_samples_all_present,
    min_public_samples_to_reconstruct, min_samples_for_two_pow_neg, orig_beats_public_recovery,
    recover_hidden_payload, recover_public_payload, undetected_le_two_pow_neg, undetected_ratio,
    AvailabilityKind, ReconstructError, RecoveryPath, Rs2d, Rs2dNet,
};

const TINY_F_PROD_BYTES: usize = 84_214;

fn tiny_f_grid() -> Rs2d {
    Rs2d::encode(&vec![9u8; TINY_F_PROD_BYTES])
}

#[test]
fn statement_has_no_sampling_claim() {
    assert_eq!(kind_for(178), AvailabilityKind::FullDownload { bytes: 178 });
    assert!(178 <= FULL_DOWNLOAD_MAX);
}

#[test]
fn ratio_is_reduced_and_zero_when_impossible() {
    assert_eq!(undetected_ratio(10, 10, 0), (1, 1));
    assert_eq!(undetected_ratio(3, 10, 4), (0, 1));
    let (n, d) = undetected_ratio(2, 4, 1);
    assert_eq!((n, d), (1, 2));
    assert!(undetected_le_two_pow_neg(0, 8, 1, 1));
    assert!(!undetected_le_two_pow_neg(8, 8, 1, 1));
}

#[test]
fn sixteen_hits_accept_while_complement_is_unreconstructable() {
    let mut g = tiny_f_grid();
    let idx = g.sample_indices(DEFAULT_SAMPLES);
    assert_eq!(idx.len(), DEFAULT_SAMPLES);
    drop_complement(&mut g, &idx);
    assert_eq!(g.present(), DEFAULT_SAMPLES);
    assert!(light_samples_all_present(&g, DEFAULT_SAMPLES));
    assert_eq!(g.reconstruct(), Err(ReconstructError::NeedMoreShares));
}

#[test]
fn encoder_k_plus_one_square_vs_public_samples() {
    let mut g = tiny_f_grid();
    let idx = g.sample_indices(DEFAULT_SAMPLES);
    let avoid = avoiding_squares(g.n, g.k + 1, &idx);
    eprintln!(
        "sample-soundness tiny-F k+1 squares avoiding 16 public samples: {}",
        avoid
    );
    assert_eq!(avoid, 0);
    assert!(!drop_unreconstructable_square_avoiding(&mut g, &idx));
    drop_complement(&mut g, &idx);
    assert!(light_samples_all_present(&g, DEFAULT_SAMPLES));
    assert_eq!(g.reconstruct(), Err(ReconstructError::NeedMoreShares));
}

#[test]
fn missing_row_is_reconstructable_and_often_undetected() {
    let mut g = tiny_f_grid();
    let total = g.n_cells() as u64;
    let missing = g.n as u64;
    let present = total - missing;
    g.drop_row(0);
    assert_eq!(g.reconstruct().unwrap().len(), TINY_F_PROD_BYTES);
    let (num, den) = undetected_ratio(present, total, DEFAULT_SAMPLES as u64);
    eprintln!(
        "sample-soundness missing-row k={} n={}: present={} total={} s={} undetected={}/{}",
        19, 38, present, total, DEFAULT_SAMPLES, num, den
    );
    assert_eq!(num, 3_034_010_954_072_035_750_414_443_492_995);
    assert_eq!(den, 4_659_181_932_328_512_286_034_416_989_074);
    assert!(!undetected_le_two_pow_neg(
        present,
        total,
        DEFAULT_SAMPLES as u64,
        1
    ));
    let s = min_samples_for_two_pow_neg(present, total, 40).expect("limb compare");
    assert_eq!(s, 739);
    assert!(!undetected_le_two_pow_neg(present, total, s - 1, 40));
    assert!(undetected_le_two_pow_neg(present, total, s, 40));
    eprintln!(
        "sample-soundness missing-row 2^{{-40}}: present={} total={} min unique samples={} (withhold still reconstructs; not the reconstruct count)",
        present, total, s
    );
}

#[test]
fn sixteen_is_not_two_pow_neg_forty_against_k_plus_one_square() {
    let g = tiny_f_grid();
    let total = g.n_cells() as u64;
    let hole = ((g.k + 1) * (g.k + 1)) as u64;
    let present = total - hole;
    assert_eq!(total, 38 * 38);
    assert_eq!(hole, 20 * 20);
    let (num, den) = undetected_ratio(present, total, DEFAULT_SAMPLES as u64);
    eprintln!(
        "sample-soundness k+1 square k={} n={}: present={} hole={} s=16 undetected={}/{}",
        g.k, g.n, present, hole, num, den
    );
    assert_eq!(num, 2_472_516_097_901_315_893_362_982_862_711);
    assert_eq!(den, 458_092_576_977_581_008_938_548_940_275_266);
    assert!(!undetected_le_two_pow_neg(
        present,
        total,
        DEFAULT_SAMPLES as u64,
        40
    ));
    let s = min_samples_for_two_pow_neg(present, total, 40).expect("limb compare");
    assert_eq!(s, 83);
    assert!(!undetected_le_two_pow_neg(present, total, s - 1, 40));
    assert!(undetected_le_two_pow_neg(present, total, s, 40));
    eprintln!(
        "sample-soundness k+1 square 2^{{-40}}: present={} total={} min unique samples={}",
        present, total, s
    );
}

#[test]
fn one_of_n100_replica_withhold_is_not_caught_by_sixteen() {
    let mut net = Rs2dNet::disperse(&vec![7u8; TINY_F_PROD_BYTES], 100);
    let total = net.grid.n_cells() as u64;
    net.withhold_replica(0);
    let present = net.grid.present() as u64;
    let (num, den) = undetected_ratio(present, total, DEFAULT_SAMPLES as u64);
    eprintln!(
        "sample-soundness 1-of-100 replica: present={} total={} s=16 undetected={}/{}",
        present, total, num, den
    );
    assert_eq!(num, 489_224_122_567_084_590_178_301_399_012_555);
    assert_eq!(den, 578_693_871_229_569_851_039_861_887_315_434);
    assert!(!undetected_le_two_pow_neg(
        present,
        total,
        DEFAULT_SAMPLES as u64,
        1
    ));
    let s = min_samples_for_two_pow_neg(present, total, 40).expect("limb compare");
    assert_eq!(s, 1211);
    assert!(!undetected_le_two_pow_neg(present, total, s - 1, 40));
    assert!(undetected_le_two_pow_neg(present, total, s, 40));
    eprintln!(
        "sample-soundness 1-of-100 replica 2^{{-40}}: present={} total={} min unique samples={}",
        present, total, s
    );
}

#[test]
fn public_fs_reconstruct_is_not_eighty_three() {
    let g = tiny_f_grid();
    let s = min_public_samples_to_reconstruct(&g);
    assert_eq!(s, 512);
    let mut kept = g.clone();
    let idx = kept.sample_indices(s);
    drop_complement(&mut kept, &idx);
    assert_eq!(kept.reconstruct().unwrap().len(), TINY_F_PROD_BYTES);
    let mut fewer = g.clone();
    let idx = fewer.sample_indices(s - 1);
    drop_complement(&mut fewer, &idx);
    assert_eq!(fewer.reconstruct(), Err(ReconstructError::NeedMoreShares));
    let fetched = g.light_sample(s).unwrap();
    assert_eq!(fetched, 311_296);
    eprintln!(
        "sample-soundness public FS reconstruct tiny-F: min samples={} fetched={} B (83 is 2^{{-40}} vs square, not this)",
        s, fetched
    );
}

/// The square's `2^{-40}` count is still a light-client sample, not reconstruct.
#[test]
fn eighty_three_public_hits_still_do_not_reconstruct() {
    let g = tiny_f_grid();
    let s = 83usize;
    let mut kept = g.clone();
    let idx = kept.sample_indices(s);
    assert_eq!(idx.len(), s);
    drop_complement(&mut kept, &idx);
    assert_eq!(kept.present(), s);
    assert!(light_samples_all_present(&kept, s));
    assert_eq!(kept.reconstruct(), Err(ReconstructError::NeedMoreShares));
    let fetched = g.light_sample(s).unwrap();
    assert_eq!(fetched, 50_464);
    eprintln!(
        "sample-soundness 83 public FS tiny-F: fetched={} B, light accepts, reconstruct fails (2^{{-40}} vs square ≠ reconstruct)",
        fetched
    );
}

const TAPE_PROOF_BYTES: usize = 1_291_000;
const COINS: [u8; 32] = [1u8; 32];

fn tape_grid() -> Rs2d {
    Rs2d::encode(&vec![7u8; TAPE_PROOF_BYTES])
}

/// Tape size class (`k=72`, coded 5 308 416 B). Integer counts — grid not required.
#[test]
fn tape_size_class_two_pow_neg_forty_is_not_sixteen() {
    let k = 72usize;
    let n = 2 * k;
    let total = (n * n) as u64;
    assert_eq!(total, 20_736);
    let square_present = total - ((k + 1) * (k + 1)) as u64;
    assert_eq!(square_present, 15_407);
    let row_present = total - n as u64;
    assert_eq!(row_present, 20_592);
    // Stripe `i % 100 == 0` over `0..total` drops `(total + 99) / 100` cells.
    let replica_present = total - (total + 99) / 100;
    assert_eq!(replica_present, 20_528);

    let s_sq = min_samples_for_two_pow_neg(square_present, total, 40).expect("limbs");
    let s_row = min_samples_for_two_pow_neg(row_present, total, 40).expect("limbs");
    let s_rep = min_samples_for_two_pow_neg(replica_present, total, 40).expect("limbs");
    assert_eq!(s_sq, 94);
    assert_eq!(s_row, 3_620);
    assert_eq!(s_rep, 2_575);
    assert!(!undetected_le_two_pow_neg(
        square_present,
        total,
        DEFAULT_SAMPLES as u64,
        40
    ));
    assert!(!undetected_le_two_pow_neg(square_present, total, s_sq - 1, 40));
    assert!(undetected_le_two_pow_neg(square_present, total, s_sq, 40));
    assert!(!undetected_le_two_pow_neg(row_present, total, s_row - 1, 40));
    assert!(undetected_le_two_pow_neg(row_present, total, s_row, 40));
    assert!(!undetected_le_two_pow_neg(replica_present, total, s_rep - 1, 40));
    assert!(undetected_le_two_pow_neg(replica_present, total, s_rep, 40));
    eprintln!(
        "sample-soundness tape k=72 n=144 total={}: 2^{{-40}} square={} missing-row={} 1-of-100={} (16 is none; not reconstruct)",
        total, s_sq, s_row, s_rep
    );
}

/// The tape square's `2^{-40}` count is still a light-client sample, not reconstruct.
#[test]
fn ninety_four_public_hits_still_do_not_reconstruct_tape() {
    let g = tape_grid();
    let s = 94usize;
    let mut kept = g.clone();
    let idx = kept.sample_indices(s);
    assert_eq!(idx.len(), s);
    drop_complement(&mut kept, &idx);
    assert_eq!(kept.present(), s);
    assert!(light_samples_all_present(&kept, s));
    assert_eq!(kept.reconstruct(), Err(ReconstructError::NeedMoreShares));
    let fetched = g.light_sample(s).unwrap();
    assert_eq!(fetched, 69_184);
    eprintln!(
        "sample-soundness 94 public FS tape k=72: fetched={} B, light accepts, reconstruct fails (2^{{-40}} vs square ≠ reconstruct)",
        fetched
    );
}

/// Public FS reconstruct of tape `k=72`. Not `2^{-40}` (94). Not `π`.
#[test]
fn public_fs_reconstruct_tape_is_not_ninety_four() {
    let t0 = std::time::Instant::now();
    let g = tape_grid();
    let s = min_public_samples_to_reconstruct(&g);
    let search_ms = t0.elapsed().as_millis();
    assert_eq!(s, 8_621);
    let mut kept = g.clone();
    let idx = kept.sample_indices(s);
    drop_complement(&mut kept, &idx);
    assert_eq!(kept.reconstruct().unwrap().len(), TAPE_PROOF_BYTES);
    let mut fewer = g.clone();
    let idx = fewer.sample_indices(s - 1);
    drop_complement(&mut fewer, &idx);
    assert_eq!(fewer.reconstruct(), Err(ReconstructError::NeedMoreShares));
    let fetched = g.light_sample(s).unwrap();
    assert_eq!(fetched, 6_345_056);
    // Merkle openings for 8621 cells exceed the coded grid (5 308 416 B).
    assert!(fetched > g.coded_bytes());
    eprintln!(
        "sample-soundness public FS reconstruct tape k=72: min samples={} fetched={} B > coded {} B search={} ms (94 is 2^{{-40}} vs square, not this)",
        s,
        fetched,
        g.coded_bytes(),
        search_ms
    );
}

/// Recovery: tiny-`F` prefers sample-reconstruct; tape prefers coded download.
#[test]
fn cheaper_public_recovery_picks_by_size() {
    let tiny = tiny_f_grid();
    let (tiny_path, tiny_bytes) = cheaper_public_recovery(&tiny);
    assert_eq!(
        tiny_path,
        RecoveryPath::PublicSample { samples: 512 }
    );
    assert_eq!(tiny_bytes, 311_296);
    assert!(tiny_bytes < tiny.coded_bytes());

    let tape = tape_grid();
    let (tape_path, tape_bytes) = cheaper_public_recovery(&tape);
    assert_eq!(tape_path, RecoveryPath::CodedGrid);
    assert_eq!(tape_bytes, 5_308_416);
    assert!(tape_bytes < tape.light_sample(8_621).unwrap());
    eprintln!(
        "recovery cheaper: tiny-F {:?} {} B (coded {}); tape {:?} {} B (sample-recon {})",
        tiny_path,
        tiny_bytes,
        tiny.coded_bytes(),
        tape_path,
        tape_bytes,
        tape.light_sample(8_621).unwrap()
    );
}

/// Hidden recovery mirrors public size pick; uncoded orig beats both.
#[test]
fn cheaper_hidden_recovery_and_orig_beats_public() {
    let tiny = tiny_f_grid();
    let (tiny_path, tiny_bytes) = cheaper_hidden_recovery(&tiny, &COINS);
    assert_eq!(
        tiny_path,
        RecoveryPath::HiddenSample { samples: 495 }
    );
    assert_eq!(tiny_bytes, 300_960);
    assert!(tiny_bytes < tiny.coded_bytes());
    assert!(orig_beats_public_recovery(&tiny));
    assert_eq!(tiny.bytes_len, TINY_F_PROD_BYTES);

    let tape = tape_grid();
    let (tape_path, tape_bytes) = cheaper_hidden_recovery(&tape, &COINS);
    assert_eq!(tape_path, RecoveryPath::CodedGrid);
    assert_eq!(tape_bytes, 5_308_416);
    assert!(tape_bytes < tape.light_sample_hidden(&COINS, 8_421).unwrap());
    assert!(orig_beats_public_recovery(&tape));
    assert_eq!(tape.bytes_len, TAPE_PROOF_BYTES);
    eprintln!(
        "recovery hidden: tiny-F {:?} {} B; tape {:?} {} B; orig beats public ({} / {})",
        tiny_path,
        tiny_bytes,
        tape_path,
        tape_bytes,
        tiny.bytes_len,
        tape.bytes_len
    );
}

/// Recovery API returns the payload on the cheaper path (not light 16).
#[test]
fn recover_public_payload_both_sizes() {
    let tiny_bytes = vec![9u8; TINY_F_PROD_BYTES];
    let tiny = Rs2d::encode(&tiny_bytes);
    let (tiny_path, got, tiny_cost) = recover_public_payload(&tiny).unwrap();
    assert_eq!(tiny_path, RecoveryPath::PublicSample { samples: 512 });
    assert_eq!(got, tiny_bytes);
    assert_eq!(tiny_cost, 311_296);

    let tape_bytes = vec![7u8; TAPE_PROOF_BYTES];
    let tape = Rs2d::encode(&tape_bytes);
    let (tape_path, got, tape_cost) = recover_public_payload(&tape).unwrap();
    assert_eq!(tape_path, RecoveryPath::CodedGrid);
    assert_eq!(got, tape_bytes);
    assert_eq!(tape_cost, 5_308_416);

    let (hpath, hgot, hcost) = recover_hidden_payload(&tiny, &COINS).unwrap();
    assert_eq!(hpath, RecoveryPath::HiddenSample { samples: 495 });
    assert_eq!(hgot, tiny_bytes);
    assert_eq!(hcost, 300_960);
    eprintln!(
        "recover_public_payload: tiny-F {:?} {} B; tape {:?} {} B; hidden tiny-F {:?} {} B",
        tiny_path, tiny_cost, tape_path, tape_cost, hpath, hcost
    );
}

/// Tape coded path still recovers after a missing row (sample path is not used).
#[test]
fn recover_public_coded_path_survives_missing_row_on_tape() {
    let want = vec![5u8; TAPE_PROOF_BYTES];
    let mut g = Rs2d::encode(&want);
    assert_eq!(cheaper_public_recovery(&g).0, RecoveryPath::CodedGrid);
    g.drop_row(0);
    assert_eq!(g.reconstruct().unwrap(), want);
    eprintln!(
        "recover coded path tape k=72: missing row reconstructs to {} B (path stays CodedGrid on full grid)",
        want.len()
    );
}

#[test]
fn k_plus_one_square_exceeds_half_the_coded_grid() {
    for k in [19usize, 72] {
        let n = 2 * k;
        let side = k + 1;
        assert!(side * 2 > n);
        assert!(side * side + DEFAULT_SAMPLES < n * n);
    }
}
