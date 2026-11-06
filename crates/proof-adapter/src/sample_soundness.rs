//! Counting argument for n≫4 public sampling (Q-DA-6).
//!
//! [`sample_indices`](commitments::sample_indices) is a function of `blob_root`.
//! The encoder therefore knows the 16 cells a light client will fetch. That is
//! not a hiding sample. It is not a soundness proof that those hits imply the
//! network can reconstruct. Not KZG. Not `π`. [`HeightStatement`] (178 B)
//! still full-downloads.
//!
//! Ratios are gcd-reduced integers. Compare to `2^{-lambda}` with integer
//! limbs when the reduced fraction does not fit in `u128`. No floats.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::rs2d::Rs2d;

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// `P(all samples land in `present` of `total`)` as a reduced fraction.
///
/// Unique samples without replacement (hypergeometric). If `samples` exceeds
/// `present`, the probability is 0.
pub fn undetected_ratio(present: u64, total: u64, samples: u64) -> (u128, u128) {
    try_undetected_ratio(present, total, samples).expect("undetected ratio fits u128")
}

fn try_undetected_ratio(present: u64, total: u64, samples: u64) -> Option<(u128, u128)> {
    assert!(present <= total);
    if samples == 0 {
        return Some((1, 1));
    }
    if samples > present || total == 0 {
        return Some((0, 1));
    }
    let mut num = 1u128;
    let mut den = 1u128;
    for i in 0..samples {
        num = num.checked_mul((present - i) as u128)?;
        den = den.checked_mul((total - i) as u128)?;
        let g = gcd(num, den);
        num /= g;
        den /= g;
    }
    Some((num, den))
}

/// `num/den ≤ 2^{-lambda}` with integer compare. Overflow of `num << lambda`
/// means the ratio is larger than `2^{-lambda}`.
pub fn ratio_le_two_pow_neg(num: u128, den: u128, lambda: u32) -> bool {
    if den == 0 {
        return false;
    }
    if num == 0 {
        return true;
    }
    if lambda == 0 {
        return num <= den;
    }
    if lambda >= 128 {
        return false;
    }
    num.checked_shl(lambda)
        .map(|shifted| shifted <= den)
        .unwrap_or(false)
}

pub fn undetected_le_two_pow_neg(present: u64, total: u64, samples: u64, lambda: u32) -> bool {
    match try_undetected_ratio(present, total, samples) {
        Some((num, den)) => ratio_le_two_pow_neg(num, den, lambda),
        None => undetected_le_two_pow_neg_limbs(present, total, samples, lambda),
    }
}

/// `Π (present-i) · 2^lambda ≤ Π (total-i)`. Little-endian `u64` limbs.
/// Used when the reduced fraction does not fit in `u128`. Not a float log.
fn undetected_le_two_pow_neg_limbs(present: u64, total: u64, samples: u64, lambda: u32) -> bool {
    assert!(present <= total);
    if samples == 0 {
        return lambda == 0;
    }
    if samples > present || total == 0 {
        return true;
    }
    let mut num = vec![1u64];
    let mut den = vec![1u64];
    for i in 0..samples {
        mul_u64(&mut num, present - i);
        mul_u64(&mut den, total - i);
    }
    shl_limbs(&mut num, lambda);
    cmp_limbs(&num, &den) != Ordering::Greater
}

fn mul_u64(limbs: &mut Vec<u64>, m: u64) {
    if m == 0 {
        limbs.clear();
        limbs.push(0);
        return;
    }
    let mut carry = 0u128;
    for x in limbs.iter_mut() {
        let t = *x as u128 * m as u128 + carry;
        *x = t as u64;
        carry = t >> 64;
    }
    if carry > 0 {
        limbs.push(carry as u64);
    }
}

fn shl_limbs(limbs: &mut Vec<u64>, bits: u32) {
    if bits == 0 || limbs.iter().all(|&x| x == 0) {
        return;
    }
    let words = (bits / 64) as usize;
    let b = bits % 64;
    if words > 0 {
        limbs.splice(0..0, std::iter::repeat(0).take(words));
    }
    if b == 0 {
        return;
    }
    let mut carry = 0u64;
    for x in limbs.iter_mut() {
        let t = (*x as u128) << b;
        *x = t as u64 | carry;
        carry = (t >> 64) as u64;
    }
    if carry > 0 {
        limbs.push(carry);
    }
}

fn cmp_limbs(a: &[u64], b: &[u64]) -> Ordering {
    let a = trim_limbs(a);
    let b = trim_limbs(b);
    match a.len().cmp(&b.len()) {
        Ordering::Equal => {
            for (x, y) in a.iter().rev().zip(b.iter().rev()) {
                match x.cmp(y) {
                    Ordering::Equal => {}
                    o => return o,
                }
            }
            Ordering::Equal
        }
        o => o,
    }
}

fn trim_limbs(limbs: &[u64]) -> &[u64] {
    let n = limbs.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    &limbs[..n]
}

/// Smallest unique-sample count with undetected probability `≤ 2^{-lambda}`.
/// `None` only when every feasible count has probability 1 (`present == total`).
pub fn min_samples_for_two_pow_neg(present: u64, total: u64, lambda: u32) -> Option<u64> {
    if total == 0 {
        return Some(0);
    }
    if present == total {
        return None;
    }
    for s in 0..=present {
        if undetected_le_two_pow_neg(present, total, s, lambda) {
            return Some(s);
        }
    }
    Some(present + 1)
}

pub fn light_samples_all_present(grid: &Rs2d, samples: usize) -> bool {
    grid.sample_indices(samples)
        .iter()
        .all(|&i| grid.open(i).is_some())
}

pub fn light_samples_all_present_hidden(grid: &Rs2d, coins: &[u8; 32], samples: usize) -> bool {
    grid.sample_indices_hidden(coins, samples)
        .iter()
        .all(|&i| grid.open(i).is_some())
}

pub fn drop_square(grid: &mut Rs2d, r0: usize, c0: usize, side: usize) {
    for r in r0..r0 + side {
        for c in c0..c0 + side {
            grid.drop_cell(r, c);
        }
    }
}

/// How many top-left positions of a `side×side` square on an `n×n` grid avoid `cells`.
pub fn avoiding_squares(n: usize, side: usize, cells: &[usize]) -> usize {
    if side > n {
        return 0;
    }
    let forbid: BTreeSet<usize> = cells.iter().copied().collect();
    let mut count = 0usize;
    for r0 in 0..=n - side {
        for c0 in 0..=n - side {
            let mut hits = false;
            'sq: for r in r0..r0 + side {
                for c in c0..c0 + side {
                    if forbid.contains(&(r * n + c)) {
                        hits = true;
                        break 'sq;
                    }
                }
            }
            if !hits {
                count += 1;
            }
        }
    }
    count
}

pub fn first_avoiding_square(n: usize, side: usize, cells: &[usize]) -> Option<(usize, usize)> {
    if side > n {
        return None;
    }
    let forbid: BTreeSet<usize> = cells.iter().copied().collect();
    for r0 in 0..=n - side {
        for c0 in 0..=n - side {
            let mut hits = false;
            'sq: for r in r0..r0 + side {
                for c in c0..c0 + side {
                    if forbid.contains(&(r * n + c)) {
                        hits = true;
                        break 'sq;
                    }
                }
            }
            if !hits {
                return Some((r0, c0));
            }
        }
    }
    None
}

pub fn drop_unreconstructable_square_avoiding(grid: &mut Rs2d, avoid: &[usize]) -> bool {
    let Some((r0, c0)) = first_avoiding_square(grid.n, grid.k + 1, avoid) else {
        return false;
    };
    drop_square(grid, r0, c0, grid.k + 1);
    true
}

fn min_kept_samples_to_reconstruct(grid: &Rs2d, keep: impl Fn(&Rs2d, usize) -> Vec<usize>) -> usize {
    let n = grid.n_cells();
    let mut lo = 0usize;
    let mut hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let mut g = grid.clone();
        let idx = keep(&g, mid);
        drop_complement(&mut g, &idx);
        if g.reconstruct().is_ok() {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

/// Smallest public Fiat–Shamir sample count whose kept cells reconstruct.
/// Encoder-known indices. Not `2^{-40}`. Not `π`.
pub fn min_public_samples_to_reconstruct(grid: &Rs2d) -> usize {
    min_kept_samples_to_reconstruct(grid, |g, s| g.sample_indices(s))
}

/// How a recovery node obtains the payload under public DA.
/// Light 16-sample is detection only. Not `π`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryPath {
    /// Download all coded cells (raw chunks; verify Merkle root of leaves).
    CodedGrid,
    /// Fetch enough public FS Merkle openings that 2D RS reconstructs.
    PublicSample { samples: usize },
    /// Fetch enough hidden-coin Merkle openings that 2D RS reconstructs.
    HiddenSample { samples: usize },
}

/// Cheaper of coded-grid download vs public FS sample-to-reconstruct.
/// Research default for recovery nodes (not light clients).
pub fn cheaper_public_recovery(grid: &Rs2d) -> (RecoveryPath, usize) {
    let coded = grid.coded_bytes();
    let samples = min_public_samples_to_reconstruct(grid);
    let sample_bytes = grid
        .light_sample(samples)
        .expect("full grid present for cost compare");
    if coded <= sample_bytes {
        (RecoveryPath::CodedGrid, coded)
    } else {
        (RecoveryPath::PublicSample { samples }, sample_bytes)
    }
}

/// Smallest hidden-sample count whose kept cells reconstruct this grid.
/// Constructive for these coins. Not `2^{-40}`. Not `π`.
pub fn min_hidden_samples_to_reconstruct(grid: &Rs2d, coins: &[u8; 32]) -> usize {
    min_kept_samples_to_reconstruct(grid, |g, s| g.sample_indices_hidden(coins, s))
}

/// Cheaper of coded-grid download vs hidden sample-to-reconstruct for `coins`.
/// Client-local; encoder who knows only `root` cannot precompute the sample set.
pub fn cheaper_hidden_recovery(grid: &Rs2d, coins: &[u8; 32]) -> (RecoveryPath, usize) {
    let coded = grid.coded_bytes();
    let samples = min_hidden_samples_to_reconstruct(grid, coins);
    let sample_bytes = grid
        .light_sample_hidden(coins, samples)
        .expect("full grid present for cost compare");
    if coded <= sample_bytes {
        (RecoveryPath::CodedGrid, coded)
    } else {
        (RecoveryPath::HiddenSample { samples }, sample_bytes)
    }
}

/// Uncoded payload size when an honest party still offers it.
/// Always beats `cheaper_public_recovery` on the measured fixtures.
pub fn orig_beats_public_recovery(grid: &Rs2d) -> bool {
    let (_, recovery) = cheaper_public_recovery(grid);
    grid.bytes_len < recovery
}

/// Recover payload via [`cheaper_public_recovery`]. Requires a full grid for
/// path selection. Returns `(path, payload, wire_bytes)`. Not light-client.
/// Not `π`.
pub fn recover_public_payload(
    grid: &Rs2d,
) -> Result<(RecoveryPath, Vec<u8>, usize), crate::ReconstructError> {
    let (path, cost) = cheaper_public_recovery(grid);
    let bytes = match path {
        RecoveryPath::CodedGrid => {
            let mut g = grid.clone();
            g.reconstruct()?
        }
        RecoveryPath::PublicSample { samples } => {
            let mut g = grid.clone();
            let idx = g.sample_indices(samples);
            drop_complement(&mut g, &idx);
            g.reconstruct()?
        }
        RecoveryPath::HiddenSample { .. } => {
            unreachable!("cheaper_public_recovery never returns HiddenSample")
        }
    };
    Ok((path, bytes, cost))
}

/// Recover payload via [`cheaper_hidden_recovery`] for `coins`.
/// Requires a full grid for path selection. Not `π`.
pub fn recover_hidden_payload(
    grid: &Rs2d,
    coins: &[u8; 32],
) -> Result<(RecoveryPath, Vec<u8>, usize), crate::ReconstructError> {
    let (path, cost) = cheaper_hidden_recovery(grid, coins);
    let bytes = match path {
        RecoveryPath::CodedGrid => {
            let mut g = grid.clone();
            g.reconstruct()?
        }
        RecoveryPath::HiddenSample { samples } => {
            let mut g = grid.clone();
            let idx = g.sample_indices_hidden(coins, samples);
            drop_complement(&mut g, &idx);
            g.reconstruct()?
        }
        RecoveryPath::PublicSample { .. } => {
            unreachable!("cheaper_hidden_recovery never returns PublicSample")
        }
    };
    Ok((path, bytes, cost))
}

/// Keep only `keep` cells. Encoder-known sample set: light client accepts,
/// reconstruction fails.
pub fn drop_complement(grid: &mut Rs2d, keep: &[usize]) {
    let keep: BTreeSet<usize> = keep.iter().copied().collect();
    let n = grid.n;
    for i in 0..grid.n_cells() {
        if !keep.contains(&i) {
            grid.drop_cell(i / n, i % n);
        }
    }
}
