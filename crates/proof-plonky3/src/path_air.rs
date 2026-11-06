//! Round-per-row AIR of a Poseidon2-16 compression path.
//!
//! [`PATH_LEN`] is the `C'` upsert count (20). [`ENGINE_INSERT_LEN`] is
//! the engine-insert count (72). Neither is `C'`. `C'` is BLAKE3 (ADR 0013).
//! Official `default_babybear_poseidon2_16()` lockstep. Degree-2 sbox.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    default_babybear_poseidon2_16, GenericPoseidon2LinearLayersBabyBear,
    BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL, BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    BABYBEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::Permutation;
use p3_uni_stark::{prove, verify};

use crate::{field, make_config, FriClass, Plonky3VerifyError, ProofReport, ProveError, Val};
use tiny_f::TinyFError;

/// `C'` upsert hash count at 8k. Not a BLAKE3 count in this AIR.
pub const PATH_LEN: usize = 20;
/// Engine insert at 8k (3 prio + 69 node). Not `C'`.
pub const ENGINE_INSERT_LEN: usize = 72;
const W: usize = 16;
const DIGEST: usize = 8;
const N_EXT: usize = 4;
const N_INT: usize = 13;
/// Initial MDS + 4 external + 13 internal + 4 terminal external.
const ROUNDS: usize = 1 + N_EXT + N_INT + N_EXT;
const COL_S: usize = 0;
const COL_RC: usize = COL_S + W;
const COL_X2: usize = COL_RC + W;
const COL_X4: usize = COL_X2 + W;
const COL_X6: usize = COL_X4 + W;
const COL_X7: usize = COL_X6 + W;
const COL_OUT: usize = COL_X7 + W;
const COL_R: usize = COL_OUT + W;
const COL_PAD: usize = COL_R + ROUNDS;
const COL_END: usize = COL_PAD + 1;
const COL_SEEN: usize = COL_END + 1;
const COL_SIB: usize = COL_SEEN + 1;
const WIDTH: usize = COL_SIB + DIGEST;
const PIS: usize = DIGEST * 2;

type Lin = GenericPoseidon2LinearLayersBabyBear;

pub struct PathAir;

/// Leaf plus siblings. Root is official Poseidon2-16 squeeze of the path.
#[derive(Clone, Debug)]
pub struct PathStatement {
    pub leaf: [Val; DIGEST],
    pub siblings: Vec<[Val; DIGEST]>,
}

impl PathStatement {
    pub fn root(&self) -> [Val; DIGEST] {
        poseidon2_path(self.leaf, &self.siblings)
    }
}

pub fn unit_path(n: usize) -> PathStatement {
    let mut leaf = [Val::ZERO; DIGEST];
    for (j, slot) in leaf.iter_mut().enumerate() {
        *slot = field(1 + j as u64);
    }
    let siblings = (0..n)
        .map(|i| {
            let mut s = [Val::ZERO; DIGEST];
            for (j, slot) in s.iter_mut().enumerate() {
                *slot = field(100 + (i as u64) * 8 + j as u64);
            }
            s
        })
        .collect();
    PathStatement { leaf, siblings }
}

pub fn poseidon2_compress(left: [Val; DIGEST], right: [Val; DIGEST]) -> [Val; DIGEST] {
    let mut state = [Val::ZERO; W];
    state[..DIGEST].copy_from_slice(&left);
    state[DIGEST..].copy_from_slice(&right);
    default_babybear_poseidon2_16().permute_mut(&mut state);
    let mut out = [Val::ZERO; DIGEST];
    out.copy_from_slice(&state[..DIGEST]);
    out
}

pub fn poseidon2_path(leaf: [Val; DIGEST], siblings: &[[Val; DIGEST]]) -> [Val; DIGEST] {
    let mut d = leaf;
    for sib in siblings {
        d = poseidon2_compress(d, *sib);
    }
    d
}

fn sbox(x: Val) -> (Val, Val, Val, Val) {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    let x7 = x6 * x;
    (x2, x4, x6, x7)
}

fn rc_for(round: usize) -> [Val; W] {
    let mut rc = [Val::ZERO; W];
    match round {
        1..=4 => rc = BABYBEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL[round - 1],
        5..=17 => rc[0] = BABYBEAR_POSEIDON2_RC_16_INTERNAL[round - 5],
        18..=21 => rc = BABYBEAR_POSEIDON2_RC_16_EXTERNAL_FINAL[round - 18],
        _ => {}
    }
    rc
}

fn apply_round(state: [Val; W], round: usize) -> [Val; W] {
    match round {
        0 => {
            let mut s = state;
            Lin::external_linear_layer(&mut s);
            s
        }
        1..=4 | 18..=21 => {
            let mut s = state;
            let rc = rc_for(round);
            for j in 0..W {
                let (_, _, _, x7) = sbox(s[j] + rc[j]);
                s[j] = x7;
            }
            Lin::external_linear_layer(&mut s);
            s
        }
        5..=17 => {
            let mut s = state;
            let rc = rc_for(round);
            let (_, _, _, x7) = sbox(s[0] + rc[0]);
            s[0] = x7;
            Lin::internal_linear_layer(&mut s);
            s
        }
        _ => state,
    }
}

fn permute_rounds(mut state: [Val; W]) -> [Val; W] {
    for r in 0..ROUNDS {
        state = apply_round(state, r);
    }
    state
}

impl<F> BaseAir<F> for PathAir {
    fn width(&self) -> usize {
        WIDTH
    }

    fn num_public_values(&self) -> usize {
        PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut cols: Vec<usize> = (COL_S..COL_S + W).collect();
        cols.extend(COL_OUT..COL_OUT + W);
        cols.extend(COL_R..COL_R + ROUNDS);
        cols.push(COL_PAD);
        cols.push(COL_END);
        cols.push(COL_SEEN);
        cols.extend(COL_SIB..COL_SIB + DIGEST);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for PathAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };

        let pad = cur[COL_PAD];
        let end = cur[COL_END];
        let seen = cur[COL_SEEN];
        builder.assert_bool(pad);
        builder.assert_bool(end);
        builder.assert_bool(seen);

        let mut r_sum = pad.into();
        let r: Vec<AB::Var> = (0..ROUNDS).map(|i| cur[COL_R + i]).collect();
        for &ri in &r {
            builder.assert_bool(ri);
            r_sum = r_sum + ri.into();
        }
        builder.assert_one(r_sum);
        builder.assert_zero(end * pad);
        builder.assert_zero(end * (AB::Expr::ONE - r[ROUNDS - 1]));

        let k_init = r[0].into();
        let mut k_ext = AB::Expr::ZERO;
        for i in 1..=4 {
            k_ext = k_ext + r[i].into();
        }
        for i in 18..=21 {
            k_ext = k_ext + r[i].into();
        }
        let mut k_int = AB::Expr::ZERO;
        for i in 5..=17 {
            k_int = k_int + r[i].into();
        }

        for j in 0..W {
            let mut rc_expr = AB::Expr::ZERO;
            for i in 0..ROUNDS {
                rc_expr = rc_expr + AB::Expr::from(rc_for(i)[j]) * r[i];
            }
            builder.assert_eq(cur[COL_RC + j], rc_expr);
            let pre = cur[COL_S + j] + cur[COL_RC + j];
            builder.assert_eq(cur[COL_X2 + j], pre.clone() * pre.clone());
            builder.assert_eq(cur[COL_X4 + j], cur[COL_X2 + j] * cur[COL_X2 + j]);
            builder.assert_eq(cur[COL_X6 + j], cur[COL_X4 + j] * cur[COL_X2 + j]);
            builder.assert_eq(cur[COL_X7 + j], cur[COL_X6 + j] * pre);
        }

        let mut from_s: [AB::Expr; W] = std::array::from_fn(|j| cur[COL_S + j].into());
        Lin::external_linear_layer(&mut from_s);
        let mut from_x7: [AB::Expr; W] = std::array::from_fn(|j| cur[COL_X7 + j].into());
        Lin::external_linear_layer(&mut from_x7);
        let mut from_int: [AB::Expr; W] = std::array::from_fn(|j| {
            if j == 0 {
                cur[COL_X7].into()
            } else {
                cur[COL_S + j].into()
            }
        });
        Lin::internal_linear_layer(&mut from_int);

        for j in 0..W {
            let want = k_init.clone() * from_s[j].clone()
                + k_ext.clone() * from_x7[j].clone()
                + k_int.clone() * from_int[j].clone()
                + pad * cur[COL_S + j];
            builder.assert_eq(cur[COL_OUT + j], want);
        }

        {
            let mut first = builder.when_first_row();
            first.assert_zero(pad);
            first.assert_zero(end);
            first.assert_zero(seen);
            first.assert_one(r[0]);
            for i in 1..ROUNDS {
                first.assert_zero(r[i]);
            }
            for j in 0..DIGEST {
                first.assert_eq(cur[COL_S + j], pis[j]);
                first.assert_eq(cur[COL_S + DIGEST + j], cur[COL_SIB + j]);
            }
        }
        {
            let mut last = builder.when_last_row();
            last.assert_one(seen + end);
        }
        {
            let mut at_end = builder.when(end);
            for j in 0..DIGEST {
                at_end.assert_eq(cur[COL_OUT + j], pis[DIGEST + j]);
            }
        }

        // r21 and pad are exclusive (sum(r)+pad=1). end implies r21.
        let wrap = r[ROUNDS - 1] - end;
        let cont = AB::Expr::ONE - r[ROUNDS - 1] - pad;
        {
            let mut t = builder.when_transition();
            t.assert_eq(nxt[COL_PAD], pad + end);
            t.assert_eq(nxt[COL_SEEN], seen + end);
            t.assert_eq(nxt[COL_R], wrap.clone());
            for i in 1..ROUNDS {
                t.assert_eq(nxt[COL_R + i], r[i - 1] * cont.clone());
            }
            for j in 0..DIGEST {
                t.assert_eq(nxt[COL_S + j], cur[COL_OUT + j]);
            }
            for j in 0..DIGEST {
                t.assert_eq(
                    nxt[COL_S + DIGEST + j],
                    (AB::Expr::ONE - wrap.clone()) * cur[COL_OUT + DIGEST + j]
                        + wrap.clone() * nxt[COL_SIB + j],
                );
            }
        }
    }
}

fn public_values(stmt: &PathStatement) -> Result<Vec<Val>, TinyFError> {
    if stmt.siblings.is_empty() {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let root = stmt.root();
    let mut pis = Vec::with_capacity(PIS);
    pis.extend_from_slice(&stmt.leaf);
    pis.extend_from_slice(&root);
    Ok(pis)
}

fn generate_trace(stmt: &PathStatement) -> Result<RowMajorMatrix<Val>, TinyFError> {
    if stmt.siblings.is_empty() {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let n = stmt.siblings.len();
    let active = n * ROUNDS;
    let rows = (active + 1).next_power_of_two();
    let mut values = vec![Val::ZERO; rows * WIDTH];
    let mut digest = stmt.leaf;
    let mut seen = Val::ZERO;
    for h in 0..n {
        let mut state = [Val::ZERO; W];
        state[..DIGEST].copy_from_slice(&digest);
        state[DIGEST..].copy_from_slice(&stmt.siblings[h]);
        for r in 0..ROUNDS {
            let row_i = h * ROUNDS + r;
            let row = &mut values[row_i * WIDTH..(row_i + 1) * WIDTH];
            let rc = rc_for(r);
            let out = apply_round(state, r);
            let end = if h + 1 == n && r + 1 == ROUNDS {
                Val::ONE
            } else {
                Val::ZERO
            };
            fill_round_row(
                row,
                state,
                rc,
                out,
                r,
                Val::ZERO,
                end,
                seen,
                stmt.siblings[h],
            );
            state = out;
            if end == Val::ONE {
                seen = Val::ONE;
            }
        }
        digest.copy_from_slice(&state[..DIGEST]);
    }
    let last_out: [Val; W] = {
        let last = &values[(active - 1) * WIDTH..active * WIDTH];
        std::array::from_fn(|j| last[COL_OUT + j])
    };
    for i in active..rows {
        let row = &mut values[i * WIDTH..(i + 1) * WIDTH];
        fill_round_row(
            row,
            last_out,
            [Val::ZERO; W],
            last_out,
            ROUNDS,
            Val::ONE,
            Val::ZERO,
            Val::ONE,
            [Val::ZERO; DIGEST],
        );
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}

#[allow(clippy::too_many_arguments)]
fn fill_round_row(
    row: &mut [Val],
    state: [Val; W],
    rc: [Val; W],
    out: [Val; W],
    round: usize,
    pad: Val,
    end: Val,
    seen: Val,
    sib: [Val; DIGEST],
) {
    for j in 0..W {
        row[COL_S + j] = state[j];
        row[COL_RC + j] = rc[j];
        let (x2, x4, x6, x7) = sbox(state[j] + rc[j]);
        row[COL_X2 + j] = x2;
        row[COL_X4 + j] = x4;
        row[COL_X6 + j] = x6;
        row[COL_X7 + j] = x7;
        row[COL_OUT + j] = out[j];
    }
    if round < ROUNDS {
        row[COL_R + round] = Val::ONE;
    }
    row[COL_PAD] = pad;
    row[COL_END] = end;
    row[COL_SEEN] = seen;
    for j in 0..DIGEST {
        row[COL_SIB + j] = sib[j];
    }
}

#[derive(Clone, Debug)]
pub struct PathProof {
    pub bytes: Vec<u8>,
}

pub fn prove_path_with(stmt: PathStatement, class: FriClass) -> Result<PathProof, ProveError> {
    let config = make_config(class);
    let trace = generate_trace(&stmt)?;
    let pis = public_values(&stmt)?;
    let proof = prove(&config, &PathAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(PathProof { bytes })
}

pub fn verify_path_with(
    stmt: PathStatement,
    proof: &PathProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_values(&stmt)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &PathAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_path_and_report_with(
    stmt: PathStatement,
    class: FriClass,
) -> Result<(PathProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_path_with(stmt.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_path_with(stmt, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stepper_matches_official() {
        let mut state = [Val::ZERO; W];
        for (j, slot) in state.iter_mut().enumerate() {
            *slot = field(1 + j as u64);
        }
        let mut official = state;
        default_babybear_poseidon2_16().permute_mut(&mut official);
        assert_eq!(permute_rounds(state), official);
    }

    #[test]
    fn path20_matches_official() {
        let s = unit_path(PATH_LEN);
        assert_eq!(s.siblings.len(), 20);
        assert_eq!(s.root(), poseidon2_path(s.leaf, &s.siblings));
    }

    #[test]
    fn path72_matches_official() {
        let s = unit_path(ENGINE_INSERT_LEN);
        assert_eq!(s.siblings.len(), 72);
        assert_eq!(s.root(), poseidon2_path(s.leaf, &s.siblings));
    }

    #[test]
    fn path_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(&PathAir, AirLayout::from_air::<Val>(&PathAir));
        eprintln!("path AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_path_n1() {
        let s = unit_path(1);
        let (proof, report) = prove_path_and_report_with(s, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 poseidon2-path n=1 test: prove {} ms, verify {} ms, {} bytes, FRI {} (not C')",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_path_n20() {
        let s = unit_path(PATH_LEN);
        let (proof, report) = prove_path_and_report_with(s, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 poseidon2-path n=20 test: prove {} ms, verify {} ms, {} bytes, FRI {} (not C')",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_path_n1_prod() {
        let s = unit_path(1);
        let (_, report) = prove_path_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 poseidon2-path n=1 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (not C')",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_path_n20_prod() {
        let s = unit_path(PATH_LEN);
        let (_, report) = prove_path_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 poseidon2-path n=20 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (not C')",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_path_n20_prod_again() {
        let s = unit_path(PATH_LEN);
        let (_, report) = prove_path_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 poseidon2-path n=20 prod run2: prove {} ms, verify {} ms, {} bytes (not C')",
            report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_path_n72() {
        let s = unit_path(ENGINE_INSERT_LEN);
        let (proof, report) = prove_path_and_report_with(s, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 poseidon2-path n=72 test: prove {} ms, verify {} ms, {} bytes, FRI {} (not C')",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_path_n72_prod() {
        let s = unit_path(ENGINE_INSERT_LEN);
        let (_, report) = prove_path_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 poseidon2-path n=72 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (not C')",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_path_n72_prod_again() {
        let s = unit_path(ENGINE_INSERT_LEN);
        let (_, report) = prove_path_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 poseidon2-path n=72 prod run2: prove {} ms, verify {} ms, {} bytes (not C')",
            report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }
}
