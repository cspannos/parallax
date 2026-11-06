//! Plonky3 AIR of [`tiny_f::book_step`]. Two asks, not an 8k book, not height `π`.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use tiny_f::{BookStepStatement, TinyFError, QTY_BITS};

use crate::{
    field, make_config, FriClass, Plonky3VerifyError, ProofReport, ProveError, Val, TRACE_ROWS,
};

const COL_R0Q: usize = 0;
const COL_R0P: usize = 1;
const COL_R1Q: usize = 2;
const COL_R1P: usize = 3;
const COL_TQ: usize = 4;
const COL_TP: usize = 5;
const COL_F0: usize = 6;
const COL_REM0: usize = 7;
const COL_N0: usize = 8;
const COL_F1: usize = 9;
const COL_REM1: usize = 10;
const COL_N1: usize = 11;
const COL_TLEFT: usize = 12;
const COL_X0: usize = 13;
const COL_NX0: usize = 14;
const COL_X1: usize = 15;
const COL_NX1: usize = 16;
const COL_MIN0: usize = 17;
const COL_MIN1: usize = 18;
const COL_TAFTER: usize = 19;
const COL_BITS: usize = 20;
const NBITS: usize = QTY_BITS as usize;
const NG: usize = 13;
const WIDTH: usize = COL_BITS + NBITS * NG;
pub(crate) const BOOK_WIDTH: usize = WIDTH;
pub(crate) const BOOK_PIS: usize = PIS;
const PIS: usize = 13;

const G_R0_MIN: usize = 0;
const G_T_MIN0: usize = 1;
const G_REM0: usize = 2;
const G_GE0: usize = 3;
const G_LT0: usize = 4;
const G_R1_MIN: usize = 5;
const G_TA_MIN1: usize = 6;
const G_REM1: usize = 7;
const G_GE1: usize = 8;
const G_LT1: usize = 9;
const G_BOOK: usize = 10;
const G_TAFTER: usize = 11;
const G_TLEFT: usize = 12;

pub struct BookAir;

impl<F> BaseAir<F> for BookAir {
    fn width(&self) -> usize {
        WIDTH
    }

    fn num_public_values(&self) -> usize {
        PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for BookAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: Vec<AB::PublicVar> = (0..PIS).map(|i| pv[i]).collect();
            let cur: Vec<AB::Var> = (0..WIDTH).map(|i| main.current(i).unwrap()).collect();
            (pis, cur)
        };
        eval_book(builder, &cur, &pis);
    }
}

pub(crate) fn eval_book<AB: AirBuilder>(builder: &mut AB, cur: &[AB::Var], pis: &[AB::PublicVar]) {
    let r0q = cur[COL_R0Q];
    let r0p = cur[COL_R0P];
    let r1q = cur[COL_R1Q];
    let r1p = cur[COL_R1P];
    let tq = cur[COL_TQ];
    let tp = cur[COL_TP];
    let f0 = cur[COL_F0];
    let rem0 = cur[COL_REM0];
    let n0 = cur[COL_N0];
    let f1 = cur[COL_F1];
    let rem1 = cur[COL_REM1];
    let n1 = cur[COL_N1];
    let tleft = cur[COL_TLEFT];
    let x0 = cur[COL_X0];
    let nx0 = cur[COL_NX0];
    let x1 = cur[COL_X1];
    let nx1 = cur[COL_NX1];
    let min0 = cur[COL_MIN0];
    let min1 = cur[COL_MIN1];
    let tafter = cur[COL_TAFTER];

    builder.assert_eq(r0q, pis[0]);
    builder.assert_eq(r0p, pis[1]);
    builder.assert_eq(r1q, pis[2]);
    builder.assert_eq(r1p, pis[3]);
    builder.assert_eq(tq, pis[4]);
    builder.assert_eq(tp, pis[5]);
    builder.assert_eq(f0, pis[6]);
    builder.assert_eq(rem0, pis[7]);
    builder.assert_eq(n0, pis[8]);
    builder.assert_eq(f1, pis[9]);
    builder.assert_eq(rem1, pis[10]);
    builder.assert_eq(n1, pis[11]);
    builder.assert_eq(tleft, pis[12]);

    let book_slack = bits::<AB>(builder, cur, G_BOOK);
    builder.assert_eq(r1p, r0p + book_slack);

    eval_level::<AB>(
        builder, cur, r0q, r0p, tq, tp, f0, rem0, n0, x0, nx0, min0, G_R0_MIN, G_T_MIN0, G_GE0,
        G_LT0, G_REM0,
    );
    let tafter_bits = bits::<AB>(builder, cur, G_TAFTER);
    builder.assert_eq(tafter, tafter_bits);
    builder.assert_eq(tq, tafter + f0);
    eval_level::<AB>(
        builder, cur, r1q, r1p, tafter, tp, f1, rem1, n1, x1, nx1, min1, G_R1_MIN, G_TA_MIN1,
        G_GE1, G_LT1, G_REM1,
    );
    let tleft_bits = bits::<AB>(builder, cur, G_TLEFT);
    builder.assert_eq(tleft, tleft_bits);
    builder.assert_eq(tafter, tleft + f1);
}

fn eval_level<AB: AirBuilder>(
    builder: &mut AB,
    cur: &[AB::Var],
    rest_q: AB::Var,
    rest_p: AB::Var,
    take_q: AB::Var,
    take_p: AB::Var,
    fill: AB::Var,
    rem: AB::Var,
    notional: AB::Var,
    cross: AB::Var,
    ncross: AB::Var,
    min_q: AB::Var,
    g_rest_min: usize,
    g_take_min: usize,
    g_ge: usize,
    g_lt: usize,
    g_rem: usize,
) {
    builder.assert_bool(cross);
    builder.assert_bool(ncross);
    builder.assert_one(cross + ncross);
    builder.assert_zero((min_q - rest_q) * (min_q - take_q));
    let rest_minus_min = bits::<AB>(builder, cur, g_rest_min);
    let take_minus_min = bits::<AB>(builder, cur, g_take_min);
    builder.assert_eq(rest_q - min_q, rest_minus_min);
    builder.assert_eq(take_q - min_q, take_minus_min);
    builder.assert_eq(fill, cross * min_q);
    let rem_bits = bits::<AB>(builder, cur, g_rem);
    builder.assert_eq(rem, rem_bits);
    builder.assert_eq(rest_q, rem + fill);
    builder.assert_eq(fill * rest_p, notional);
    let slack_ge = bits::<AB>(builder, cur, g_ge);
    let slack_lt = bits::<AB>(builder, cur, g_lt);
    builder.assert_zero(cross * (take_p - rest_p - slack_ge));
    builder.assert_zero(ncross * (rest_p - take_p - AB::Expr::ONE - slack_lt));
}

fn bits<AB: AirBuilder>(builder: &mut AB, cur: &[AB::Var], group: usize) -> AB::Expr {
    let start = COL_BITS + group * NBITS;
    let mut acc = AB::Expr::ZERO;
    let mut pow = AB::Expr::ONE;
    for i in 0..NBITS {
        let b = cur[start + i];
        builder.assert_bool(b);
        acc = acc + b.into() * pow.clone();
        pow = pow.clone() + pow;
    }
    acc
}

pub(crate) fn book_public_values(stmt: &BookStepStatement) -> Result<[Val; PIS], TinyFError> {
    stmt.check()?;
    let n0 =
        u64::try_from(stmt.output.level0.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
    let n1 =
        u64::try_from(stmt.output.level1.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
    Ok([
        field(stmt.instance.rest0_qty.0),
        field(stmt.instance.rest0_price.0),
        field(stmt.instance.rest1_qty.0),
        field(stmt.instance.rest1_price.0),
        field(stmt.instance.take_qty.0),
        field(stmt.instance.take_price.0),
        field(stmt.output.level0.fill_qty.0),
        field(stmt.output.level0.remainder.0),
        field(n0),
        field(stmt.output.level1.fill_qty.0),
        field(stmt.output.level1.remainder.0),
        field(n1),
        field(stmt.output.take_left.0),
    ])
}

pub(crate) fn generate_book_row(stmt: &BookStepStatement) -> Result<Vec<Val>, TinyFError> {
    let pis = book_public_values(stmt)?;
    let r0q = stmt.instance.rest0_qty.0;
    let r0p = stmt.instance.rest0_price.0;
    let r1q = stmt.instance.rest1_qty.0;
    let r1p = stmt.instance.rest1_price.0;
    let tq = stmt.instance.take_qty.0;
    let tp = stmt.instance.take_price.0;
    let f0 = stmt.output.level0.fill_qty.0;
    let tafter = tq - f0;
    let min0 = r0q.min(tq);
    let min1 = r1q.min(tafter);
    let mut row = vec![Val::ZERO; WIDTH];
    row[COL_R0Q] = pis[0];
    row[COL_R0P] = pis[1];
    row[COL_R1Q] = pis[2];
    row[COL_R1P] = pis[3];
    row[COL_TQ] = pis[4];
    row[COL_TP] = pis[5];
    row[COL_F0] = pis[6];
    row[COL_REM0] = pis[7];
    row[COL_N0] = pis[8];
    row[COL_F1] = pis[9];
    row[COL_REM1] = pis[10];
    row[COL_N1] = pis[11];
    row[COL_TLEFT] = pis[12];
    row[COL_X0] = field(u64::from(stmt.output.level0.crosses));
    row[COL_NX0] = field(u64::from(!stmt.output.level0.crosses));
    row[COL_X1] = field(u64::from(stmt.output.level1.crosses));
    row[COL_NX1] = field(u64::from(!stmt.output.level1.crosses));
    row[COL_MIN0] = field(min0);
    row[COL_MIN1] = field(min1);
    row[COL_TAFTER] = field(tafter);
    put_bits(&mut row, G_R0_MIN, r0q - min0);
    put_bits(&mut row, G_T_MIN0, tq - min0);
    put_bits(&mut row, G_REM0, stmt.output.level0.remainder.0);
    put_bits(&mut row, G_GE0, tp.saturating_sub(r0p));
    put_bits(&mut row, G_LT0, r0p.saturating_sub(tp).saturating_sub(1));
    put_bits(&mut row, G_R1_MIN, r1q - min1);
    put_bits(&mut row, G_TA_MIN1, tafter - min1);
    put_bits(&mut row, G_REM1, stmt.output.level1.remainder.0);
    put_bits(&mut row, G_GE1, tp.saturating_sub(r1p));
    put_bits(&mut row, G_LT1, r1p.saturating_sub(tp).saturating_sub(1));
    put_bits(&mut row, G_BOOK, r1p - r0p);
    put_bits(&mut row, G_TAFTER, tafter);
    put_bits(&mut row, G_TLEFT, stmt.output.take_left.0);
    Ok(row)
}

fn generate_trace(stmt: &BookStepStatement) -> Result<RowMajorMatrix<Val>, TinyFError> {
    let row = generate_book_row(stmt)?;
    let mut values = Vec::with_capacity(TRACE_ROWS * WIDTH);
    for _ in 0..TRACE_ROWS {
        values.extend_from_slice(&row);
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
pub struct BookProof {
    pub bytes: Vec<u8>,
}

pub fn prove_book(stmt: BookStepStatement) -> Result<BookProof, ProveError> {
    prove_book_with(stmt, FriClass::Test)
}

pub fn prove_book_with(stmt: BookStepStatement, class: FriClass) -> Result<BookProof, ProveError> {
    let config = make_config(class);
    let trace = generate_trace(&stmt)?;
    let pis = book_public_values(&stmt)?;
    let proof = prove(&config, &BookAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(BookProof { bytes })
}

pub fn verify_book(stmt: BookStepStatement, proof: &BookProof) -> Result<(), Plonky3VerifyError> {
    verify_book_with(stmt, proof, FriClass::Test)
}

pub fn verify_book_with(
    stmt: BookStepStatement,
    proof: &BookProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = book_public_values(&stmt)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &BookAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_book_and_report(
    stmt: BookStepStatement,
) -> Result<(BookProof, ProofReport), ProveError> {
    prove_book_and_report_with(stmt, FriClass::Test)
}

pub fn prove_book_and_report_with(
    stmt: BookStepStatement,
    class: FriClass,
) -> Result<(BookProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_book_with(stmt, class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_book_with(stmt, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{Price, Qty};
    use tiny_f::BookStepInstance;

    fn walk() -> BookStepStatement {
        BookStepStatement::prove_native(BookStepInstance {
            rest0_qty: Qty(5),
            rest0_price: Price(80),
            rest1_qty: Qty(10),
            rest1_price: Price(90),
            take_qty: Qty(12),
            take_price: Price(100),
        })
        .unwrap()
    }

    #[test]
    fn prove_verify_two_level_walk() {
        let s = walk();
        let (proof, report) = prove_book_and_report(s).unwrap();
        assert!(proof.bytes.len() > 32);
        assert_eq!(report.fri_queries, 2);
        eprintln!(
            "plonky3 book-step test: prove {} ms, verify {} ms, {} bytes, FRI queries {}",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_verify_two_level_walk_prod() {
        let s = walk();
        let (proof, report) = prove_book_and_report_with(s, FriClass::Prod).unwrap();
        assert_eq!(report.fri_queries, 100);
        assert!(report.official_poseidon);
        eprintln!(
            "plonky3 book-step prod: prove {} ms, verify {} ms, {} bytes, FRI queries {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
        assert!(proof.bytes.len() > 32);
    }

    #[test]
    fn different_statement_rejected() {
        let s = walk();
        let proof = prove_book(s).unwrap();
        let other = BookStepStatement::prove_native(BookStepInstance {
            rest0_qty: Qty(5),
            rest0_price: Price(80),
            rest1_qty: Qty(10),
            rest1_price: Price(90),
            take_qty: Qty(3),
            take_price: Price(100),
        })
        .unwrap();
        assert!(verify_book(other, &proof).is_err());
    }
}
