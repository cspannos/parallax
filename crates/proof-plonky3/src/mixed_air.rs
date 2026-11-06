//! Row-per-event AIR of [`tiny_f::mixed_f`]. Rest/take/cancel, not `C'`, not 8k.
//!
//! Eight slots. Empty start. Takes hit the unique-price best rest. Poseidon2
//! in the FRI sponge is not the treap.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use tiny_f::{MixedStatement, TinyFError, MIX_NOTIONAL_BITS, MIX_SLOTS, QTY_BITS};

use crate::{field, make_config, FriClass, Plonky3VerifyError, ProofReport, ProveError, Val};

const N: usize = MIX_SLOTS;
const COL_KR: usize = 0;
const COL_KT: usize = 1;
const COL_KC: usize = 2;
const COL_EQ: usize = 3;
const COL_EP: usize = 4;
const COL_SLOT: usize = 5;
const COL_FILL: usize = 6;
const COL_REM: usize = 7;
const COL_N: usize = 8;
const COL_ACC_F: usize = 9;
const COL_ACC_N: usize = 10;
const COL_X: usize = 11;
const COL_NX: usize = 12;
const COL_MIN: usize = 13;
const COL_BEST_Q: usize = 14;
const COL_BEST_P: usize = 15;
const COL_Q: usize = 16;
const COL_P: usize = COL_Q + N;
const COL_QO: usize = COL_P + N;
const COL_PO: usize = COL_QO + N;
const COL_BEST: usize = COL_PO + N;
const COL_EMPTY: usize = COL_BEST + N;
const COL_OCC: usize = COL_EMPTY + N;
const COL_C: usize = COL_OCC + N;
const COL_TMP: usize = COL_C + N;
const COL_SEL: usize = COL_TMP + N;
const COL_BITS: usize = COL_SEL + N;
const NBITS: usize = QTY_BITS as usize;
const G_RMIN: usize = 0;
const G_TMIN: usize = 1;
const G_REM: usize = 2;
const G_GE: usize = 3;
const G_LT: usize = 4;
const G_ACC_F: usize = 5;
const G_ACC_N: usize = 6;
const G_QSLACK: usize = 7;
const G_PGT: usize = G_QSLACK + N;
const NG: usize = G_PGT + N;
const ACC_N_EXT: usize = MIX_NOTIONAL_BITS as usize - NBITS;
const COL_ACC_N_EXT: usize = COL_BITS + NBITS * NG;
const WIDTH: usize = COL_ACC_N_EXT + ACC_N_EXT;
const PIS: usize = 2;

pub struct MixedAir;

impl<F> BaseAir<F> for MixedAir {
    fn width(&self) -> usize {
        WIDTH
    }

    fn num_public_values(&self) -> usize {
        PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut cols = vec![COL_FILL, COL_N, COL_ACC_F, COL_ACC_N];
        cols.extend(COL_Q..COL_Q + N);
        cols.extend(COL_P..COL_P + N);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for MixedAir {
    fn eval(&self, builder: &mut AB) {
        let (p_fsum, p_nsum, cur, nxt) = {
            let main = builder.main();
            let pis = builder.public_values();
            (
                pis[0],
                pis[1],
                main.current_slice().to_vec(),
                main.next_slice().to_vec(),
            )
        };

        let kr = cur[COL_KR];
        let kt = cur[COL_KT];
        let kc = cur[COL_KC];
        let eq = cur[COL_EQ];
        let ep = cur[COL_EP];
        let slot = cur[COL_SLOT];
        let fill = cur[COL_FILL];
        let rem = cur[COL_REM];
        let n = cur[COL_N];
        let acc_f = cur[COL_ACC_F];
        let acc_n = cur[COL_ACC_N];
        let x = cur[COL_X];
        let nx = cur[COL_NX];
        let min_q = cur[COL_MIN];
        let best_q = cur[COL_BEST_Q];
        let best_p = cur[COL_BEST_P];

        builder.assert_bool(kr);
        builder.assert_bool(kt);
        builder.assert_bool(kc);
        builder.assert_one(kr + kt + kc);
        builder.assert_bool(x);
        builder.assert_bool(nx);
        builder.assert_zero(kt * (x + nx - AB::Expr::ONE));
        builder.assert_zero((AB::Expr::ONE - kt) * x);

        let rmin = bits::<AB>(builder, G_RMIN);
        let tmin = bits::<AB>(builder, G_TMIN);
        builder.assert_zero((min_q - best_q) * (min_q - eq));
        builder.assert_eq(best_q - min_q, rmin);
        builder.assert_eq(eq - min_q, tmin);
        builder.assert_eq(fill, x * min_q);
        builder.assert_eq(fill * best_p, n);
        let ge = bits::<AB>(builder, G_GE);
        let lt = bits::<AB>(builder, G_LT);
        builder.assert_zero(x * (ep - best_p - ge));
        builder.assert_zero(nx * (best_p - ep - AB::Expr::ONE - lt));
        let rem_b = bits::<AB>(builder, G_REM);
        builder.assert_eq(rem, rem_b);
        let acc_fb = bits::<AB>(builder, G_ACC_F);
        let acc_n_lo = bits::<AB>(builder, G_ACC_N);
        let acc_n_hi = bits_ext::<AB>(builder);
        let mut hi_pow = AB::Expr::ONE;
        for _ in 0..NBITS {
            hi_pow = hi_pow.clone() + hi_pow;
        }
        builder.assert_eq(acc_f, acc_fb);
        builder.assert_eq(acc_n, acc_n_lo + acc_n_hi * hi_pow);

        let mut sum_e = AB::Expr::ZERO;
        let mut sum_b = AB::Expr::ZERO;
        let mut sum_c = AB::Expr::ZERO;
        let mut sum_best_q = AB::Expr::ZERO;
        let mut sum_best_p = AB::Expr::ZERO;
        let mut sum_slot = AB::Expr::ZERO;
        let mut cancel_q = AB::Expr::ZERO;

        for i in 0..N {
            let q = cur[COL_Q + i];
            let p = cur[COL_P + i];
            let qo = cur[COL_QO + i];
            let po = cur[COL_PO + i];
            let b = cur[COL_BEST + i];
            let e = cur[COL_EMPTY + i];
            let occ = cur[COL_OCC + i];
            let c = cur[COL_C + i];
            let tmp = cur[COL_TMP + i];
            let sel = cur[COL_SEL + i];
            builder.assert_bool(b);
            builder.assert_bool(e);
            builder.assert_bool(occ);
            builder.assert_bool(c);
            builder.assert_zero(q * (AB::Expr::ONE - occ));
            let slack = bits::<AB>(builder, G_QSLACK + i);
            builder.assert_eq(q, occ + slack);
            builder.assert_zero(e * occ);
            builder.assert_zero(b * (AB::Expr::ONE - occ));
            builder.assert_zero(c * (AB::Expr::ONE - occ));
            builder.assert_eq(tmp, kt * occ);
            builder.assert_eq(sel, tmp * (AB::Expr::ONE - b));
            let gt = bits::<AB>(builder, G_PGT + i);
            builder.assert_zero(sel * (p - best_p - AB::Expr::ONE - gt));
            builder.assert_zero(b * (p - best_p));
            for j in 0..i {
                builder.assert_zero(e * (AB::Expr::ONE - cur[COL_OCC + j]));
            }
            sum_e = sum_e + e.into();
            sum_b = sum_b + b.into();
            sum_c = sum_c + c.into();
            sum_best_q = sum_best_q + b * q;
            sum_best_p = sum_best_p + b * p;
            let ii = AB::Expr::from_u64(i as u64);
            sum_slot = sum_slot + ii * (e + b + c);
            cancel_q = cancel_q + c * q;
            builder.assert_eq(qo, q + e * eq - b * fill - c * q);
            builder.assert_eq(po, e * ep + (AB::Expr::ONE - e) * p);
        }
        builder.assert_eq(sum_e, kr.into());
        builder.assert_eq(sum_b, kt.into());
        builder.assert_eq(sum_c, kc.into());
        builder.assert_eq(best_q, sum_best_q);
        builder.assert_eq(best_p, sum_best_p);
        builder.assert_eq(slot, sum_slot);
        builder.assert_zero(kt * (rem - (best_q - fill)));
        builder.assert_zero(kr * (rem - eq));
        builder.assert_eq(kc * rem, cancel_q);

        {
            let mut first = builder.when_first_row();
            first.assert_eq(acc_f, fill);
            first.assert_eq(acc_n, n);
            for i in 0..N {
                first.assert_zero(cur[COL_Q + i]);
            }
        }
        {
            let mut last = builder.when_last_row();
            last.assert_eq(acc_f, p_fsum);
            last.assert_eq(acc_n, p_nsum);
        }
        {
            let mut t = builder.when_transition();
            t.assert_eq(nxt[COL_ACC_F], acc_f + nxt[COL_FILL]);
            t.assert_eq(nxt[COL_ACC_N], acc_n + nxt[COL_N]);
            for i in 0..N {
                t.assert_eq(nxt[COL_Q + i], cur[COL_QO + i]);
                t.assert_eq(nxt[COL_P + i], cur[COL_PO + i]);
            }
        }
    }
}

fn bits<AB: AirBuilder>(builder: &mut AB, group: usize) -> AB::Expr {
    bit_run::<AB>(builder, COL_BITS + group * NBITS, NBITS)
}

fn bits_ext<AB: AirBuilder>(builder: &mut AB) -> AB::Expr {
    bit_run::<AB>(builder, COL_ACC_N_EXT, ACC_N_EXT)
}

fn bit_run<AB: AirBuilder>(builder: &mut AB, start: usize, n: usize) -> AB::Expr {
    let bit_vars: Vec<AB::Var> = {
        let main = builder.main();
        (0..n).map(|i| main.current(start + i).unwrap()).collect()
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

fn public_values(stmt: &MixedStatement) -> Result<[Val; PIS], TinyFError> {
    stmt.check()?;
    if stmt.instance.slots.iter().any(|(q, _)| q.0 != 0) {
        return Err(TinyFError::OutsideInstanceClass);
    }
    let n =
        u64::try_from(stmt.output.notional_sum).map_err(|_| TinyFError::OutsideInstanceClass)?;
    Ok([field(stmt.output.fill_sum.0), field(n)])
}

fn generate_trace(stmt: &MixedStatement) -> Result<RowMajorMatrix<Val>, TinyFError> {
    let _ = public_values(stmt)?;
    let k = stmt.instance.events.len();
    let mut values = Vec::with_capacity(k * WIDTH);
    let mut slots = stmt.instance.slots.clone();
    let mut acc_f = 0u64;
    let mut acc_n = 0u64;
    for (ev, out) in stmt.instance.events.iter().zip(stmt.output.events.iter()) {
        acc_f += out.fill_qty.0;
        acc_n += u64::try_from(out.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
        let mut row = vec![Val::ZERO; WIDTH];
        match ev.kind {
            tiny_f::MixKind::Rest => row[COL_KR] = field(1),
            tiny_f::MixKind::Take => row[COL_KT] = field(1),
            tiny_f::MixKind::Cancel => row[COL_KC] = field(1),
        }
        row[COL_EQ] = field(ev.qty.0);
        row[COL_EP] = field(ev.price.0);
        row[COL_SLOT] = field(out.slot);
        row[COL_FILL] = field(out.fill_qty.0);
        row[COL_REM] = field(out.remainder.0);
        let n = u64::try_from(out.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
        row[COL_N] = field(n);
        row[COL_ACC_F] = field(acc_f);
        row[COL_ACC_N] = field(acc_n);

        let occ: Vec<bool> = slots.iter().map(|(q, _)| q.0 > 0).collect();
        let empty_i = slots.iter().position(|(q, _)| q.0 == 0);
        let best_i = slots
            .iter()
            .enumerate()
            .filter(|(_, (q, _))| q.0 > 0)
            .min_by_key(|(i, (_, p))| (p.0, *i))
            .map(|(i, _)| i);
        let is_take = matches!(ev.kind, tiny_f::MixKind::Take);
        let (best_q, best_p) = if is_take {
            match best_i {
                Some(i) => (slots[i].0 .0, slots[i].1 .0),
                None => (0, 0),
            }
        } else {
            (0, 0)
        };
        row[COL_BEST_Q] = field(best_q);
        row[COL_BEST_P] = field(best_p);
        let min_q = best_q.min(ev.qty.0);
        row[COL_MIN] = field(min_q);
        let crosses = is_take && ev.price.0 >= best_p;
        row[COL_X] = field(u64::from(crosses));
        row[COL_NX] = field(u64::from(is_take && !crosses));

        for i in 0..N {
            row[COL_Q + i] = field(slots[i].0 .0);
            row[COL_P + i] = field(slots[i].1 .0);
            row[COL_OCC + i] = field(u64::from(occ[i]));
            put_bits(
                &mut row,
                G_QSLACK + i,
                slots[i].0 .0.saturating_sub(u64::from(occ[i])),
            );
            if matches!(ev.kind, tiny_f::MixKind::Rest) && empty_i == Some(i) {
                row[COL_EMPTY + i] = field(1);
            }
            if matches!(ev.kind, tiny_f::MixKind::Take) && best_i == Some(i) {
                row[COL_BEST + i] = field(1);
            }
            if matches!(ev.kind, tiny_f::MixKind::Cancel) && ev.slot == i as u64 {
                row[COL_C + i] = field(1);
            }
            let tmp = matches!(ev.kind, tiny_f::MixKind::Take) && occ[i];
            row[COL_TMP + i] = field(u64::from(tmp));
            let sel = tmp && best_i != Some(i);
            row[COL_SEL + i] = field(u64::from(sel));
            let gt = if sel {
                slots[i].1 .0.saturating_sub(best_p).saturating_sub(1)
            } else {
                0
            };
            put_bits(&mut row, G_PGT + i, gt);
        }

        // apply
        match ev.kind {
            tiny_f::MixKind::Rest => {
                let i = empty_i.expect("rest empty");
                slots[i] = (ev.qty, ev.price);
            }
            tiny_f::MixKind::Take => {
                let i = best_i.expect("take best");
                slots[i].0 = out.remainder;
            }
            tiny_f::MixKind::Cancel => {
                slots[ev.slot as usize] = (protocol_types::Qty(0), slots[ev.slot as usize].1);
            }
        }
        for i in 0..N {
            row[COL_QO + i] = field(slots[i].0 .0);
            row[COL_PO + i] = field(slots[i].1 .0);
        }

        put_bits(&mut row, G_RMIN, best_q.saturating_sub(min_q));
        put_bits(&mut row, G_TMIN, ev.qty.0.saturating_sub(min_q));
        put_bits(&mut row, G_REM, out.remainder.0);
        put_bits(&mut row, G_GE, ev.price.0.saturating_sub(best_p));
        put_bits(
            &mut row,
            G_LT,
            best_p.saturating_sub(ev.price.0).saturating_sub(1),
        );
        put_bits(&mut row, G_ACC_F, acc_f);
        put_bits(&mut row, G_ACC_N, acc_n & ((1 << NBITS) - 1));
        for i in 0..ACC_N_EXT {
            row[COL_ACC_N_EXT + i] = field((acc_n >> (NBITS + i)) & 1);
        }
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
pub struct MixedProof {
    pub bytes: Vec<u8>,
}

pub fn prove_mixed_with(stmt: MixedStatement, class: FriClass) -> Result<MixedProof, ProveError> {
    let config = make_config(class);
    let trace = generate_trace(&stmt)?;
    let pis = public_values(&stmt)?;
    let proof = prove(&config, &MixedAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(MixedProof { bytes })
}

pub fn verify_mixed_with(
    stmt: MixedStatement,
    proof: &MixedProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_values(&stmt)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &MixedAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_mixed_and_report_with(
    stmt: MixedStatement,
    class: FriClass,
) -> Result<(MixedProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_mixed_with(stmt.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_mixed_with(stmt, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_f::{unit_mixed, MixedStatement};

    fn stmt(k: usize) -> MixedStatement {
        MixedStatement::prove_native(unit_mixed(k)).unwrap()
    }

    #[test]
    fn mixed_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d =
            get_max_constraint_degree::<Val, _>(&MixedAir, AirLayout::from_air::<Val>(&MixedAir));
        eprintln!("mixed AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_mixed_k8() {
        let s = stmt(8);
        let (proof, report) = prove_mixed_and_report_with(s, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 mixed k=8 test: prove {} ms, verify {} ms, {} bytes, FRI {}",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_mixed_k8_prod() {
        let s = stmt(8);
        let (_, report) = prove_mixed_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 mixed k=8 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_mixed_k32_prod() {
        let s = stmt(32);
        let (_, report) = prove_mixed_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 mixed k=32 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_mixed_k128_prod() {
        let s = stmt(128);
        let (_, report) = prove_mixed_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 mixed k=128 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_mixed_k512_prod() {
        let s = stmt(512);
        let (_, report) = prove_mixed_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 mixed k=512 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_mixed_k8192_prod() {
        let s = stmt(8192);
        let (_, report) = prove_mixed_and_report_with(s, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 mixed k=8192 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[test]
    fn different_mixed_rejected() {
        let s = stmt(8);
        let proof = prove_mixed_with(s, FriClass::Test).unwrap();
        let mut other = stmt(8);
        other.output.fill_sum = protocol_types::Qty(other.output.fill_sum.0 + 1);
        assert!(verify_mixed_with(other, &proof, FriClass::Test).is_err());
    }
}
