//! Plonky3 AIR of [`tiny_f::match_step`]. Not a book proof. Not height `π`.
//!
//! Same FRI-2 / RNG Poseidon2 as [`crate::FillAir`]. Not production soundness.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use tiny_f::{MatchStepStatement, TinyFError, QTY_BITS};

use crate::{
    field, make_config, FriClass, Plonky3VerifyError, ProofReport, ProveError, Val, TRACE_ROWS,
};

const COL_REST_Q: usize = 0;
const COL_REST_P: usize = 1;
const COL_TAKE_Q: usize = 2;
const COL_TAKE_P: usize = 3;
const COL_FILL: usize = 4;
const COL_FILL_P: usize = 5;
const COL_REM: usize = 6;
const COL_NOTIONAL: usize = 7;
const COL_CROSS: usize = 8;
const COL_NCROSS: usize = 9;
const COL_MIN: usize = 10;
const COL_BITS: usize = 11;
const NBITS: usize = QTY_BITS as usize;
const WIDTH: usize = COL_BITS + NBITS * 5;
const PIS: usize = 8;

const BIT_REST_MIN: usize = 0;
const BIT_TAKE_MIN: usize = 1;
const BIT_SLACK_GE: usize = 2;
const BIT_SLACK_LT: usize = 3;
const BIT_REM: usize = 4;

pub struct MatchAir;

impl<F> BaseAir<F> for MatchAir {
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

impl<AB: AirBuilder> Air<AB> for MatchAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: Vec<AB::PublicVar> = (0..PIS).map(|i| pv[i]).collect();
            let cur: Vec<AB::Var> = (0..WIDTH).map(|i| main.current(i).unwrap()).collect();
            (pis, cur)
        };
        eval_match(builder, &cur, &pis);
    }
}

pub(crate) const MATCH_WIDTH: usize = WIDTH;
pub(crate) const MATCH_PIS: usize = PIS;

pub(crate) fn eval_match<AB: AirBuilder>(builder: &mut AB, cur: &[AB::Var], pis: &[AB::PublicVar]) {
    let rest_q = cur[COL_REST_Q];
    let rest_p = cur[COL_REST_P];
    let take_q = cur[COL_TAKE_Q];
    let take_p = cur[COL_TAKE_P];
    let fill = cur[COL_FILL];
    let fill_p = cur[COL_FILL_P];
    let rem = cur[COL_REM];
    let notional = cur[COL_NOTIONAL];
    let cross = cur[COL_CROSS];
    let ncross = cur[COL_NCROSS];
    let min_q = cur[COL_MIN];

    builder.assert_eq(rest_q, pis[0]);
    builder.assert_eq(rest_p, pis[1]);
    builder.assert_eq(take_q, pis[2]);
    builder.assert_eq(take_p, pis[3]);
    builder.assert_eq(fill, pis[4]);
    builder.assert_eq(fill_p, pis[5]);
    builder.assert_eq(rem, pis[6]);
    builder.assert_eq(notional, pis[7]);

    builder.assert_bool(cross);
    builder.assert_bool(ncross);
    builder.assert_one(cross + ncross);

    builder.assert_zero((min_q - rest_q) * (min_q - take_q));
    let rest_minus_min = match_bits::<AB>(builder, cur, BIT_REST_MIN);
    let take_minus_min = match_bits::<AB>(builder, cur, BIT_TAKE_MIN);
    builder.assert_eq(rest_q - min_q, rest_minus_min);
    builder.assert_eq(take_q - min_q, take_minus_min);

    builder.assert_eq(fill, cross * min_q);
    let rem_bits = match_bits::<AB>(builder, cur, BIT_REM);
    builder.assert_eq(rem, rem_bits);
    builder.assert_eq(rest_q, rem + fill);

    builder.assert_eq(fill_p, rest_p);
    builder.assert_eq(fill * fill_p, notional);

    let slack_ge = match_bits::<AB>(builder, cur, BIT_SLACK_GE);
    let slack_lt = match_bits::<AB>(builder, cur, BIT_SLACK_LT);
    builder.assert_zero(cross * (take_p - rest_p - slack_ge));
    builder.assert_zero(ncross * (rest_p - take_p - AB::Expr::ONE - slack_lt));
}

fn match_bits<AB: AirBuilder>(builder: &mut AB, cur: &[AB::Var], group: usize) -> AB::Expr {
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

pub(crate) fn match_public_values(stmt: &MatchStepStatement) -> Result<[Val; PIS], TinyFError> {
    stmt.check()?;
    let n = u64::try_from(stmt.output.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
    Ok([
        field(stmt.instance.rest_qty.0),
        field(stmt.instance.rest_price.0),
        field(stmt.instance.take_qty.0),
        field(stmt.instance.take_price.0),
        field(stmt.output.fill_qty.0),
        field(stmt.output.fill_price.0),
        field(stmt.output.remainder.0),
        field(n),
    ])
}

fn generate_trace(stmt: &MatchStepStatement) -> Result<RowMajorMatrix<Val>, TinyFError> {
    let row = generate_match_row(stmt)?;
    let mut values = Vec::with_capacity(TRACE_ROWS * WIDTH);
    for _ in 0..TRACE_ROWS {
        values.extend_from_slice(&row);
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}

pub(crate) fn generate_match_row(stmt: &MatchStepStatement) -> Result<Vec<Val>, TinyFError> {
    stmt.check()?;
    let n = u64::try_from(stmt.output.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
    let rest_q = stmt.instance.rest_qty.0;
    let rest_p = stmt.instance.rest_price.0;
    let take_q = stmt.instance.take_qty.0;
    let take_p = stmt.instance.take_price.0;
    let fill = stmt.output.fill_qty.0;
    let min_q = rest_q.min(take_q);
    let mut row = vec![Val::ZERO; WIDTH];
    row[COL_REST_Q] = field(rest_q);
    row[COL_REST_P] = field(rest_p);
    row[COL_TAKE_Q] = field(take_q);
    row[COL_TAKE_P] = field(take_p);
    row[COL_FILL] = field(fill);
    row[COL_FILL_P] = field(stmt.output.fill_price.0);
    row[COL_REM] = field(stmt.output.remainder.0);
    row[COL_NOTIONAL] = field(n);
    row[COL_CROSS] = field(u64::from(stmt.output.crosses));
    row[COL_NCROSS] = field(u64::from(!stmt.output.crosses));
    row[COL_MIN] = field(min_q);
    put_bits(&mut row, BIT_REST_MIN, rest_q - min_q);
    put_bits(&mut row, BIT_TAKE_MIN, take_q - min_q);
    let slack_ge = take_p.saturating_sub(rest_p);
    let slack_lt = rest_p.saturating_sub(take_p).saturating_sub(1);
    put_bits(&mut row, BIT_SLACK_GE, slack_ge);
    put_bits(&mut row, BIT_SLACK_LT, slack_lt);
    put_bits(&mut row, BIT_REM, stmt.output.remainder.0);
    Ok(row)
}

fn put_bits(row: &mut [Val], group: usize, v: u64) {
    let start = COL_BITS + group * NBITS;
    for i in 0..NBITS {
        row[start + i] = field((v >> i) & 1);
    }
}

#[derive(Clone, Debug)]
pub struct MatchProof {
    pub bytes: Vec<u8>,
}

pub fn prove_match(stmt: MatchStepStatement) -> Result<MatchProof, ProveError> {
    prove_match_with(stmt, FriClass::Test)
}

pub fn prove_match_with(
    stmt: MatchStepStatement,
    class: FriClass,
) -> Result<MatchProof, ProveError> {
    let config = make_config(class);
    let trace = generate_trace(&stmt)?;
    let pis = match_public_values(&stmt)?;
    let proof = prove(&config, &MatchAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(MatchProof { bytes })
}

pub fn verify_match(
    stmt: MatchStepStatement,
    proof: &MatchProof,
) -> Result<(), Plonky3VerifyError> {
    verify_match_with(stmt, proof, FriClass::Test)
}

pub fn verify_match_with(
    stmt: MatchStepStatement,
    proof: &MatchProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = match_public_values(&stmt)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &MatchAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_match_and_report(
    stmt: MatchStepStatement,
) -> Result<(MatchProof, ProofReport), ProveError> {
    prove_match_and_report_with(stmt, FriClass::Test)
}

pub fn prove_match_and_report_with(
    stmt: MatchStepStatement,
    class: FriClass,
) -> Result<(MatchProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_match_with(stmt, class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_match_with(stmt, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{Price, Qty};
    use tiny_f::MatchStepInstance;

    fn cross() -> MatchStepStatement {
        MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(7),
            take_price: Price(100),
        })
        .unwrap()
    }

    #[test]
    fn prove_verify_partial_cross() {
        let s = cross();
        let (proof, report) = prove_match_and_report(s).unwrap();
        assert!(proof.bytes.len() > 32);
        assert_eq!(report.fri_queries, 2);
        eprintln!(
            "plonky3 match-step test: prove {} ms, verify {} ms, {} bytes, FRI queries {}",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_verify_partial_cross_prod() {
        let s = cross();
        let (proof, report) = prove_match_and_report_with(s, FriClass::Prod).unwrap();
        assert!(proof.bytes.len() > 32);
        assert_eq!(report.fri_queries, 100);
        assert!(report.official_poseidon);
        eprintln!(
            "plonky3 match-step prod: prove {} ms, verify {} ms, {} bytes, FRI queries {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[test]
    fn prove_verify_no_cross() {
        let s = MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(7),
            take_price: Price(89),
        })
        .unwrap();
        let proof = prove_match(s).unwrap();
        verify_match(s, &proof).unwrap();
    }

    #[test]
    fn different_statement_rejected() {
        let s = cross();
        let proof = prove_match(s).unwrap();
        let other = MatchStepStatement::prove_native(MatchStepInstance {
            rest_qty: Qty(10),
            rest_price: Price(90),
            take_qty: Qty(10),
            take_price: Price(90),
        })
        .unwrap();
        assert!(verify_match(other, &proof).is_err());
    }
}
