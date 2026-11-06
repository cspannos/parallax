//! Row-per-level AIR of [`tiny_f::book_walk`]. k asks, not an 8k book, not `C'`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use tiny_f::{BookWalkStatement, TinyFError, QTY_BITS};

use crate::{field, make_config, FriClass, Plonky3VerifyError, ProofReport, ProveError, Val};

const COL_RQ: usize = 0;
const COL_RP: usize = 1;
const COL_TIN: usize = 2;
const COL_TP: usize = 3;
const COL_FILL: usize = 4;
const COL_REM: usize = 5;
const COL_N: usize = 6;
const COL_TOUT: usize = 7;
const COL_X: usize = 8;
const COL_NX: usize = 9;
const COL_MIN: usize = 10;
const COL_ACC_F: usize = 11;
const COL_ACC_N: usize = 12;
const COL_BITS: usize = 13;
const NBITS: usize = QTY_BITS as usize;
const G_RMIN: usize = 0;
const G_TMIN: usize = 1;
const G_REM: usize = 2;
const G_GE: usize = 3;
const G_LT: usize = 4;
const G_TOUT: usize = 5;
const G_ACC_F: usize = 6;
const G_ACC_N: usize = 7;
const G_PRICE: usize = 8;
const NG: usize = 9;
const WIDTH: usize = COL_BITS + NBITS * NG;
const PIS: usize = 5;

pub struct WalkAir;

impl<F> BaseAir<F> for WalkAir {
    fn width(&self) -> usize {
        WIDTH
    }

    fn num_public_values(&self) -> usize {
        PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let start = COL_BITS + G_PRICE * NBITS;
        let mut cols = vec![COL_TIN, COL_RP, COL_FILL, COL_N, COL_ACC_F, COL_ACC_N];
        cols.extend(start..start + NBITS);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for WalkAir {
    fn eval(&self, builder: &mut AB) {
        let (
            p_tq,
            p_tp,
            p_left,
            p_fsum,
            p_nsum,
            rq,
            rp,
            tin,
            tp,
            fill,
            rem,
            n,
            tout,
            x,
            nx,
            min_q,
            acc_f,
            acc_n,
            n_tin,
            n_rp,
            n_fill,
            n_n,
            n_acc_f,
            n_acc_n,
        ) = {
            let main = builder.main();
            let pis = builder.public_values();
            (
                pis[0],
                pis[1],
                pis[2],
                pis[3],
                pis[4],
                main.current(COL_RQ).unwrap(),
                main.current(COL_RP).unwrap(),
                main.current(COL_TIN).unwrap(),
                main.current(COL_TP).unwrap(),
                main.current(COL_FILL).unwrap(),
                main.current(COL_REM).unwrap(),
                main.current(COL_N).unwrap(),
                main.current(COL_TOUT).unwrap(),
                main.current(COL_X).unwrap(),
                main.current(COL_NX).unwrap(),
                main.current(COL_MIN).unwrap(),
                main.current(COL_ACC_F).unwrap(),
                main.current(COL_ACC_N).unwrap(),
                main.next(COL_TIN).unwrap(),
                main.next(COL_RP).unwrap(),
                main.next(COL_FILL).unwrap(),
                main.next(COL_N).unwrap(),
                main.next(COL_ACC_F).unwrap(),
                main.next(COL_ACC_N).unwrap(),
            )
        };

        builder.assert_eq(tp, p_tp);
        builder.assert_bool(x);
        builder.assert_bool(nx);
        builder.assert_one(x + nx);
        builder.assert_zero((min_q - rq) * (min_q - tin));
        let rmin = bits::<AB>(builder, G_RMIN);
        let tmin = bits::<AB>(builder, G_TMIN);
        builder.assert_eq(rq - min_q, rmin);
        builder.assert_eq(tin - min_q, tmin);
        builder.assert_eq(fill, x * min_q);
        let rem_b = bits::<AB>(builder, G_REM);
        builder.assert_eq(rem, rem_b);
        builder.assert_eq(rq, rem + fill);
        builder.assert_eq(fill * rp, n);
        let ge = bits::<AB>(builder, G_GE);
        let lt = bits::<AB>(builder, G_LT);
        builder.assert_zero(x * (tp - rp - ge));
        builder.assert_zero(nx * (rp - tp - AB::Expr::ONE - lt));
        let tout_b = bits::<AB>(builder, G_TOUT);
        builder.assert_eq(tout, tout_b);
        builder.assert_eq(tin, tout + fill);
        let acc_fb = bits::<AB>(builder, G_ACC_F);
        let acc_nb = bits::<AB>(builder, G_ACC_N);
        builder.assert_eq(acc_f, acc_fb);
        builder.assert_eq(acc_n, acc_nb);

        {
            let mut first = builder.when_first_row();
            first.assert_eq(tin, p_tq);
            first.assert_eq(acc_f, fill);
            first.assert_eq(acc_n, n);
        }
        {
            let mut last = builder.when_last_row();
            last.assert_eq(tout, p_left);
            last.assert_eq(acc_f, p_fsum);
            last.assert_eq(acc_n, p_nsum);
        }
        let price_next = bits_next::<AB>(builder, G_PRICE);
        {
            let mut t = builder.when_transition();
            t.assert_eq(n_tin, tout);
            t.assert_eq(n_rp, rp + price_next);
            t.assert_eq(n_acc_f, acc_f + n_fill);
            t.assert_eq(n_acc_n, acc_n + n_n);
        }
    }
}

fn bits<AB: AirBuilder>(builder: &mut AB, group: usize) -> AB::Expr {
    bit_sum::<AB>(builder, group, false)
}

fn bits_next<AB: AirBuilder>(builder: &mut AB, group: usize) -> AB::Expr {
    bit_sum::<AB>(builder, group, true)
}

fn bit_sum<AB: AirBuilder>(builder: &mut AB, group: usize, next: bool) -> AB::Expr {
    let start = COL_BITS + group * NBITS;
    let bit_vars: Vec<AB::Var> = {
        let main = builder.main();
        (0..NBITS)
            .map(|i| {
                if next {
                    main.next(start + i).unwrap()
                } else {
                    main.current(start + i).unwrap()
                }
            })
            .collect()
    };
    let mut acc = AB::Expr::ZERO;
    let mut pow = AB::Expr::ONE;
    for b in bit_vars {
        builder.assert_bool(b);
        acc = acc + b.into() * pow.clone();
        pow = pow.clone() + pow;
    }
    acc
}

fn public_values(stmt: &BookWalkStatement) -> Result<[Val; PIS], TinyFError> {
    stmt.check()?;
    let n =
        u64::try_from(stmt.output.notional_sum).map_err(|_| TinyFError::OutsideInstanceClass)?;
    Ok([
        field(stmt.instance.take_qty.0),
        field(stmt.instance.take_price.0),
        field(stmt.output.take_left.0),
        field(stmt.output.fill_sum.0),
        field(n),
    ])
}

fn generate_trace(stmt: &BookWalkStatement) -> Result<RowMajorMatrix<Val>, TinyFError> {
    stmt.check()?;
    let k = stmt.instance.rests.len();
    if k == 0 || !k.is_power_of_two() {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let mut values = Vec::with_capacity(k * WIDTH);
    let mut take = stmt.instance.take_qty.0;
    let mut acc_f = 0u64;
    let mut acc_n = 0u64;
    let mut prev_p = stmt.instance.rests[0].1 .0;
    for (i, (&(rq, rp), lvl)) in stmt
        .instance
        .rests
        .iter()
        .zip(stmt.output.levels.iter())
        .enumerate()
    {
        let fill = lvl.fill_qty.0;
        let n = u64::try_from(lvl.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
        let tout = take - fill;
        acc_f += fill;
        acc_n += n;
        let min_q = rq.0.min(take);
        let mut row = vec![Val::ZERO; WIDTH];
        row[COL_RQ] = field(rq.0);
        row[COL_RP] = field(rp.0);
        row[COL_TIN] = field(take);
        row[COL_TP] = field(stmt.instance.take_price.0);
        row[COL_FILL] = field(fill);
        row[COL_REM] = field(lvl.remainder.0);
        row[COL_N] = field(n);
        row[COL_TOUT] = field(tout);
        row[COL_X] = field(u64::from(lvl.crosses));
        row[COL_NX] = field(u64::from(!lvl.crosses));
        row[COL_MIN] = field(min_q);
        row[COL_ACC_F] = field(acc_f);
        row[COL_ACC_N] = field(acc_n);
        put_bits(&mut row, G_RMIN, rq.0 - min_q);
        put_bits(&mut row, G_TMIN, take - min_q);
        put_bits(&mut row, G_REM, lvl.remainder.0);
        put_bits(
            &mut row,
            G_GE,
            stmt.instance.take_price.0.saturating_sub(rp.0),
        );
        put_bits(
            &mut row,
            G_LT,
            rp.0.saturating_sub(stmt.instance.take_price.0)
                .saturating_sub(1),
        );
        put_bits(&mut row, G_TOUT, tout);
        put_bits(&mut row, G_ACC_F, acc_f);
        put_bits(&mut row, G_ACC_N, acc_n);
        let slack = if i == 0 { 0 } else { rp.0 - prev_p };
        put_bits(&mut row, G_PRICE, slack);
        values.extend_from_slice(&row);
        take = tout;
        prev_p = rp.0;
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}

fn put_bits(row: &mut [Val], group: usize, v: u64) {
    let start = COL_BITS + group * NBITS;
    for i in 0..NBITS {
        row[start + i] = field((v >> i) & 1);
    }
}

#[derive(Clone, Debug)]
pub struct WalkProof {
    pub bytes: Vec<u8>,
}

pub fn prove_walk_with(stmt: BookWalkStatement, class: FriClass) -> Result<WalkProof, ProveError> {
    let config = make_config(class);
    let trace = generate_trace(&stmt)?;
    let pis = public_values(&stmt)?;
    let proof = prove(&config, &WalkAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(WalkProof { bytes })
}

pub fn verify_walk_with(
    stmt: BookWalkStatement,
    proof: &WalkProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_values(&stmt)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &WalkAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_walk_and_report_with(
    stmt: BookWalkStatement,
    class: FriClass,
) -> Result<(WalkProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_walk_with(stmt.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_walk_with(stmt, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_f::{pad_walk, unit_asks, BookWalkStatement};

    fn stmt(k: usize, take: u64) -> BookWalkStatement {
        let inst = pad_walk(unit_asks(k, take)).unwrap();
        BookWalkStatement::prove_native(inst).unwrap()
    }

    #[test]
    fn prove_walk_k8() {
        let s = stmt(8, 5);
        let (proof, report) = prove_walk_and_report_with(s, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 walk k=8 test: prove {} ms, verify {} ms, {} bytes, FRI {}",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_walk_k8_prod() {
        let s = stmt(8, 5);
        let (_, report) = prove_walk_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 walk k=8 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_walk_k32_prod() {
        let s = stmt(32, 10);
        let (_, report) = prove_walk_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 walk k=32 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_walk_k8192_prod() {
        let s = stmt(8192, 20);
        let (_, report) = prove_walk_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 walk k=8192 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_walk_k512_prod() {
        let s = stmt(512, 20);
        let (_, report) = prove_walk_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 walk k=512 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_walk_k128_prod() {
        let s = stmt(128, 20);
        let (_, report) = prove_walk_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 walk k=128 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_walk_k32_test() {
        let s = stmt(32, 10);
        let (_, report) = prove_walk_and_report_with(s, FriClass::Test).unwrap();
        eprintln!(
            "plonky3 walk k=32 test: prove {} ms, verify {} ms, {} bytes, FRI {}",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }
}
