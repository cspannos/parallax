//! Row-per-slot AIR of [`tiny_f::scan_event`]. Packed prefix book, one event.
//!
//! `n` slots are rows (an 8k book). Not `C'`. A tape is sequential scans.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};
use tiny_f::{MixKind, ScanStatement, TinyFError, QTY_BITS};

use crate::{field, make_config, FriClass, Plonky3VerifyError, ProofReport, ProveError, Val};

const COL_KR: usize = 0;
const COL_KT: usize = 1;
const COL_KC: usize = 2;
const COL_EQ: usize = 3;
const COL_EP: usize = 4;
const COL_ESLOT: usize = 5;
const COL_Q: usize = 6;
const COL_P: usize = 7;
const COL_QO: usize = 8;
const COL_PO: usize = 9;
const COL_FILL: usize = 10;
const COL_N: usize = 11;
const COL_REM: usize = 12;
const COL_X: usize = 13;
const COL_NX: usize = 14;
const COL_MIN: usize = 15;
const COL_OCC: usize = 16;
const COL_HEAD: usize = 17;
const COL_COMPACT: usize = 18;
const COL_TARGET: usize = 19;
const COL_SEEN: usize = 20;
const COL_TMP_E: usize = 21;
const COL_IDX: usize = 22;
const COL_BELOW: usize = 23;
const COL_SHIFT: usize = 24;
const COL_HF: usize = 25;
const COL_REM_NZ: usize = 26;
const COL_RQO: usize = 27;
const COL_TQO: usize = 28;
const COL_CQO: usize = 29;
const COL_RPO: usize = 30;
const COL_TPO: usize = 31;
const COL_CPO: usize = 32;
const COL_NXTQ: usize = 33;
const COL_NXTP: usize = 34;
const COL_HT: usize = 35;
const COL_SEEN_OUT: usize = 36;
const COL_BITS: usize = 37;
const NBITS: usize = QTY_BITS as usize;
const G_RMIN: usize = 0;
const G_TMIN: usize = 1;
const G_REM: usize = 2;
const G_GE: usize = 3;
const G_LT: usize = 4;
const G_QSLACK: usize = 5;
const G_IDX: usize = 6;
const G_BL: usize = 7;
const G_NB: usize = 8;
const G_REMSL: usize = 9;
const NG: usize = 10;
const WIDTH: usize = COL_BITS + NBITS * NG;
const PIS: usize = 8;

pub struct ScanAir;

impl<F> BaseAir<F> for ScanAir {
    fn width(&self) -> usize {
        WIDTH
    }

    fn num_public_values(&self) -> usize {
        PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![
            COL_KR,
            COL_KT,
            COL_KC,
            COL_EQ,
            COL_EP,
            COL_ESLOT,
            COL_Q,
            COL_P,
            COL_COMPACT,
            COL_SEEN,
            COL_IDX,
            COL_HEAD,
            COL_NXTQ,
            COL_NXTP,
            COL_SEEN_OUT,
        ]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for ScanAir {
    fn eval(&self, builder: &mut AB) {
        let (p_fill, p_n, p_kr, p_kt, p_kc, p_eq, p_ep, p_slot, cur, nxt) = {
            let main = builder.main();
            let pis = builder.public_values();
            (
                pis[0],
                pis[1],
                pis[2],
                pis[3],
                pis[4],
                pis[5],
                pis[6],
                pis[7],
                main.current_slice().to_vec(),
                main.next_slice().to_vec(),
            )
        };
        let kr = cur[COL_KR];
        let kt = cur[COL_KT];
        let kc = cur[COL_KC];
        let eq = cur[COL_EQ];
        let ep = cur[COL_EP];
        let eslot = cur[COL_ESLOT];
        let q = cur[COL_Q];
        let p = cur[COL_P];
        let qo = cur[COL_QO];
        let po = cur[COL_PO];
        let fill = cur[COL_FILL];
        let n = cur[COL_N];
        let rem = cur[COL_REM];
        let x = cur[COL_X];
        let nx = cur[COL_NX];
        let min_q = cur[COL_MIN];
        let occ = cur[COL_OCC];
        let head = cur[COL_HEAD];
        let compact = cur[COL_COMPACT];
        let target = cur[COL_TARGET];
        let seen = cur[COL_SEEN];
        let tmp_e = cur[COL_TMP_E];
        let idx = cur[COL_IDX];
        let below = cur[COL_BELOW];
        let shift = cur[COL_SHIFT];
        let hf = cur[COL_HF];
        let rem_nz = cur[COL_REM_NZ];

        builder.assert_bool(kr);
        builder.assert_bool(kt);
        builder.assert_bool(kc);
        builder.assert_one(kr + kt + kc);
        builder.assert_eq(kr, p_kr);
        builder.assert_eq(kt, p_kt);
        builder.assert_eq(kc, p_kc);
        builder.assert_eq(eq, p_eq);
        builder.assert_eq(ep, p_ep);
        builder.assert_eq(eslot, p_slot);
        for b in [
            occ, head, compact, target, seen, tmp_e, below, shift, x, nx, rem_nz,
        ] {
            builder.assert_bool(b);
        }
        builder.assert_zero(q * (AB::Expr::ONE - occ));
        let slack = bits::<AB>(builder, G_QSLACK);
        builder.assert_eq(q, occ + slack);
        builder.assert_eq(tmp_e, (AB::Expr::ONE - occ) * (AB::Expr::ONE - seen));
        builder.assert_eq(target, kr * tmp_e);
        builder.assert_eq(cur[COL_SEEN_OUT], seen + tmp_e);
        let idx_b = bits::<AB>(builder, G_IDX);
        builder.assert_eq(idx, idx_b);
        let bl = bits::<AB>(builder, G_BL);
        let nb = bits::<AB>(builder, G_NB);
        builder.assert_zero(below * (eslot - idx - AB::Expr::ONE - bl));
        builder.assert_zero((AB::Expr::ONE - below) * (idx - eslot - nb));
        builder.assert_eq(shift, kc * (AB::Expr::ONE - below));
        builder.assert_eq(hf, head * fill);
        builder.assert_zero((AB::Expr::ONE - kt) * fill);
        builder.assert_zero((AB::Expr::ONE - head) * fill);
        builder.assert_zero(cur[COL_HT] * (x + nx - AB::Expr::ONE));
        builder.assert_zero((AB::Expr::ONE - kt) * x);
        builder.assert_zero((AB::Expr::ONE - head) * x);
        builder.assert_zero((AB::Expr::ONE - head) * nx);
        let rmin = bits::<AB>(builder, G_RMIN);
        let tmin = bits::<AB>(builder, G_TMIN);
        builder.assert_zero((min_q - q) * (min_q - eq));
        builder.assert_eq(q - min_q, rmin);
        builder.assert_eq(eq - min_q, tmin);
        builder.assert_eq(fill, x * min_q);
        builder.assert_eq(n, fill * p);
        let ge = bits::<AB>(builder, G_GE);
        let lt = bits::<AB>(builder, G_LT);
        builder.assert_zero(x * (ep - p - ge));
        builder.assert_zero(nx * (p - ep - AB::Expr::ONE - lt));
        let rem_b = bits::<AB>(builder, G_REM);
        builder.assert_eq(rem, rem_b);
        let rem_sl = bits::<AB>(builder, G_REMSL);
        builder.assert_zero(rem * (AB::Expr::ONE - rem_nz));
        builder.assert_eq(rem, rem_nz + rem_sl);
        builder.assert_eq(cur[COL_HT], kt * head);
        builder.assert_zero(cur[COL_HT] * (rem - (q - fill)));
        builder.assert_zero(target * (rem - eq));
        builder.assert_zero((kr - target) * rem);

        let rqo = cur[COL_RQO];
        let tqo = cur[COL_TQO];
        let cqo = cur[COL_CQO];
        let rpo = cur[COL_RPO];
        let tpo = cur[COL_TPO];
        let cpo = cur[COL_CPO];
        let nxtq = cur[COL_NXTQ];
        let nxtp = cur[COL_NXTP];
        builder.assert_eq(rqo, q + target * eq);
        builder.assert_eq(rpo, target * ep + (AB::Expr::ONE - target) * p);
        builder.assert_eq(tqo, compact * nxtq + (AB::Expr::ONE - compact) * (q - hf));
        builder.assert_eq(tpo, compact * nxtp + (AB::Expr::ONE - compact) * p);
        builder.assert_eq(cqo, shift * nxtq + (AB::Expr::ONE - shift) * q);
        builder.assert_eq(cpo, shift * nxtp + (AB::Expr::ONE - shift) * p);
        builder.assert_eq(qo, kr * rqo + kt * tqo + kc * cqo);
        builder.assert_eq(po, kr * rpo + kt * tpo + kc * cpo);
        builder.assert_eq(compact, kc + kt * (AB::Expr::ONE - rem_nz));

        {
            let mut t = builder.when_transition();
            t.assert_eq(nxtq, nxt[COL_Q]);
            t.assert_eq(nxtp, nxt[COL_P]);
            t.assert_eq(nxt[COL_KR], kr);
            t.assert_eq(nxt[COL_KT], kt);
            t.assert_eq(nxt[COL_KC], kc);
            t.assert_eq(nxt[COL_EQ], eq);
            t.assert_eq(nxt[COL_EP], ep);
            t.assert_eq(nxt[COL_ESLOT], eslot);
            t.assert_eq(nxt[COL_COMPACT], compact);
            t.assert_eq(nxt[COL_IDX], idx + AB::Expr::ONE);
            t.assert_eq(nxt[COL_SEEN], cur[COL_SEEN_OUT]);
            t.assert_zero(nxt[COL_HEAD]);
        }
        {
            let mut last = builder.when_last_row();
            last.assert_zero(nxtq);
            last.assert_zero(nxtp);
        }
        {
            let mut first = builder.when_first_row();
            first.assert_one(head);
            first.assert_zero(seen);
            first.assert_zero(idx);
            first.assert_eq(fill, p_fill);
            first.assert_eq(n, p_n);
        }
    }
}

fn bits<AB: AirBuilder>(builder: &mut AB, group: usize) -> AB::Expr {
    let start = COL_BITS + group * NBITS;
    let bit_vars: Vec<AB::Var> = {
        let main = builder.main();
        (0..NBITS)
            .map(|i| main.current(start + i).unwrap())
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

fn public_values(stmt: &ScanStatement) -> Result<[Val; PIS], TinyFError> {
    stmt.check()?;
    let n = u64::try_from(stmt.output.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
    let (kr, kt, kc) = match stmt.instance.event.kind {
        MixKind::Rest => (1, 0, 0),
        MixKind::Take => (0, 1, 0),
        MixKind::Cancel => (0, 0, 1),
    };
    Ok([
        field(stmt.output.fill_qty.0),
        field(n),
        field(kr),
        field(kt),
        field(kc),
        field(stmt.instance.event.qty.0),
        field(stmt.instance.event.price.0),
        field(stmt.instance.event.slot),
    ])
}

fn generate_trace(stmt: &ScanStatement) -> Result<RowMajorMatrix<Val>, TinyFError> {
    let _ = public_values(stmt)?;
    let n = stmt.instance.slots.len();
    let ev = stmt.instance.event;
    let compact = match ev.kind {
        MixKind::Cancel => true,
        MixKind::Take => stmt.output.remainder.0 == 0,
        MixKind::Rest => false,
    };
    let mut values = Vec::with_capacity(n * WIDTH);
    let mut seen = false;
    for i in 0..n {
        let (q, p) = stmt.instance.slots[i];
        let (qo, po) = stmt.slots_out[i];
        let occ = q.0 > 0;
        let tmp_e = !occ && !seen;
        let target = matches!(ev.kind, MixKind::Rest) && tmp_e;
        if tmp_e {
            seen = true;
        }
        let head = i == 0;
        let below = (i as u64) < ev.slot;
        let shift = matches!(ev.kind, MixKind::Cancel) && !below;
        let is_take = matches!(ev.kind, MixKind::Take);
        let fill = if head && is_take {
            stmt.output.fill_qty.0
        } else {
            0
        };
        let notional = if head && is_take {
            u64::try_from(stmt.output.notional).map_err(|_| TinyFError::OutsideInstanceClass)?
        } else {
            0
        };
        let rem = if matches!(ev.kind, MixKind::Rest) && target {
            ev.qty.0
        } else if head && is_take {
            stmt.output.remainder.0
        } else {
            0
        };
        let rem_nz = rem > 0;
        let min_q = q.0.min(ev.qty.0);
        let crosses = head && is_take && ev.price.0 >= p.0;
        let mut row = vec![Val::ZERO; WIDTH];
        match ev.kind {
            MixKind::Rest => row[COL_KR] = field(1),
            MixKind::Take => row[COL_KT] = field(1),
            MixKind::Cancel => row[COL_KC] = field(1),
        }
        row[COL_EQ] = field(ev.qty.0);
        row[COL_EP] = field(ev.price.0);
        row[COL_ESLOT] = field(ev.slot);
        row[COL_Q] = field(q.0);
        row[COL_P] = field(p.0);
        row[COL_QO] = field(qo.0);
        row[COL_PO] = field(po.0);
        row[COL_FILL] = field(fill);
        row[COL_N] = field(notional);
        row[COL_REM] = field(rem);
        row[COL_X] = field(u64::from(crosses));
        row[COL_NX] = field(u64::from(head && is_take && !crosses));
        row[COL_MIN] = field(min_q);
        row[COL_OCC] = field(u64::from(occ));
        row[COL_HEAD] = field(u64::from(head));
        row[COL_COMPACT] = field(u64::from(compact));
        row[COL_TARGET] = field(u64::from(target));
        row[COL_SEEN] = field(u64::from(seen && !tmp_e)); // seen_in
        row[COL_TMP_E] = field(u64::from(tmp_e));
        row[COL_SEEN_OUT] = field(u64::from(seen || tmp_e));
        row[COL_IDX] = field(i as u64);
        row[COL_BELOW] = field(u64::from(below));
        row[COL_SHIFT] = field(u64::from(shift));
        row[COL_HF] = field(u64::from(head) * fill);
        row[COL_REM_NZ] = field(u64::from(rem_nz));
        row[COL_HT] = field(u64::from(is_take && head));
        let nxt_q = if i + 1 < n {
            stmt.instance.slots[i + 1].0 .0
        } else {
            0
        };
        let nxt_p = if i + 1 < n {
            stmt.instance.slots[i + 1].1 .0
        } else {
            0
        };
        let last = i + 1 == n;
        row[COL_RQO] = field(q.0 + u64::from(target) * ev.qty.0);
        row[COL_RPO] = field(if target { ev.price.0 } else { p.0 });
        row[COL_NXTQ] = field(nxt_q);
        row[COL_NXTP] = field(nxt_p);
        if last {
            row[COL_TQO] = field(if compact {
                0
            } else {
                q.0 - u64::from(head) * fill
            });
            row[COL_TPO] = field(if compact { 0 } else { p.0 });
            row[COL_CQO] = field(if shift { 0 } else { q.0 });
            row[COL_CPO] = field(if shift { 0 } else { p.0 });
        } else {
            row[COL_TQO] = field(if compact {
                nxt_q
            } else {
                q.0 - u64::from(head) * fill
            });
            row[COL_TPO] = field(if compact { nxt_p } else { p.0 });
            row[COL_CQO] = field(if shift { nxt_q } else { q.0 });
            row[COL_CPO] = field(if shift { nxt_p } else { p.0 });
        }
        put_bits(&mut row, G_RMIN, q.0.saturating_sub(min_q));
        put_bits(&mut row, G_TMIN, ev.qty.0.saturating_sub(min_q));
        put_bits(&mut row, G_REM, rem);
        put_bits(&mut row, G_GE, ev.price.0.saturating_sub(p.0));
        put_bits(
            &mut row,
            G_LT,
            p.0.saturating_sub(ev.price.0).saturating_sub(1),
        );
        put_bits(&mut row, G_QSLACK, q.0.saturating_sub(u64::from(occ)));
        put_bits(&mut row, G_IDX, i as u64);
        put_bits(
            &mut row,
            G_BL,
            ev.slot.saturating_sub(i as u64).saturating_sub(1),
        );
        put_bits(&mut row, G_NB, (i as u64).saturating_sub(ev.slot));
        put_bits(&mut row, G_REMSL, rem.saturating_sub(u64::from(rem_nz)));
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
pub struct ScanProof {
    pub bytes: Vec<u8>,
}

pub fn prove_scan_with(stmt: ScanStatement, class: FriClass) -> Result<ScanProof, ProveError> {
    let config = make_config(class);
    let trace = generate_trace(&stmt)?;
    let pis = public_values(&stmt)?;
    let proof = prove(&config, &ScanAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(ScanProof { bytes })
}

pub fn verify_scan_with(
    stmt: ScanStatement,
    proof: &ScanProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_values(&stmt)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &ScanAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_scan_and_report_with(
    stmt: ScanStatement,
    class: FriClass,
) -> Result<(ScanProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_scan_with(stmt.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_scan_with(stmt, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

/// Sequential scans of a packed book. Not one proof of the tape.
pub fn prove_scan_tape_and_report_with(
    mut slots: Vec<(protocol_types::Qty, protocol_types::Price)>,
    events: &[tiny_f::MixEvent],
    class: FriClass,
) -> Result<ProofReport, ProveError> {
    let mut prove_ms = 0u128;
    let mut verify_ms = 0u128;
    let mut proof_bytes = 0usize;
    for &event in events {
        let stmt = ScanStatement::prove_native(tiny_f::ScanInstance {
            slots: slots.clone(),
            event,
        })?;
        slots = stmt.slots_out.clone();
        let (_, r) = prove_scan_and_report_with(stmt, class)?;
        prove_ms += r.prove_ms;
        verify_ms += r.verify_ms;
        proof_bytes += r.proof_bytes;
    }
    Ok(ProofReport::for_class(
        class,
        prove_ms,
        verify_ms,
        proof_bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{Price, Qty};
    use tiny_f::{unit_scan_book, MixEvent, MixKind, ScanInstance, ScanStatement};

    fn take_stmt(n: usize) -> ScanStatement {
        ScanStatement::prove_native(ScanInstance {
            slots: unit_scan_book(n),
            event: MixEvent {
                kind: MixKind::Take,
                qty: Qty(1),
                price: Price(20_000),
                slot: 0,
            },
        })
        .unwrap()
    }

    fn cancel_stmt(n: usize) -> ScanStatement {
        ScanStatement::prove_native(ScanInstance {
            slots: unit_scan_book(n),
            event: MixEvent {
                kind: MixKind::Cancel,
                qty: Qty(0),
                price: Price(0),
                slot: (n as u64) - 1,
            },
        })
        .unwrap()
    }

    fn rest_after_cancel(n: usize) -> ScanStatement {
        let (_, slots) = tiny_f::scan_event(ScanInstance {
            slots: unit_scan_book(n),
            event: MixEvent {
                kind: MixKind::Cancel,
                qty: Qty(0),
                price: Price(0),
                slot: (n as u64) - 1,
            },
        })
        .unwrap();
        ScanStatement::prove_native(ScanInstance {
            slots,
            event: MixEvent {
                kind: MixKind::Rest,
                qty: Qty(1),
                price: Price(80 + n as u64),
                slot: 0,
            },
        })
        .unwrap()
    }

    #[test]
    fn prove_scan_k8_take() {
        let (_, report) = prove_scan_and_report_with(take_stmt(8), FriClass::Test).unwrap();
        eprintln!(
            "plonky3 scan k=8 take test: prove {} ms, {} bytes, FRI {}",
            report.prove_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[test]
    fn prove_scan_k8_cancel() {
        let (_, report) = prove_scan_and_report_with(cancel_stmt(8), FriClass::Test).unwrap();
        eprintln!(
            "plonky3 scan k=8 cancel test: prove {} ms, {} bytes, FRI {}",
            report.prove_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[test]
    fn prove_scan_k8_rest() {
        let (_, report) = prove_scan_and_report_with(rest_after_cancel(8), FriClass::Test).unwrap();
        eprintln!(
            "plonky3 scan k=8 rest test: prove {} ms, {} bytes, FRI {}",
            report.prove_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_scan_k8192_take_prod() {
        let (_, report) = prove_scan_and_report_with(take_stmt(8192), FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 scan k=8192 take prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_scan_k8192_tape_prod() {
        let report = prove_scan_tape_and_report_with(
            unit_scan_book(8192),
            &tiny_f::unit_scan_tape(8192),
            FriClass::Prod,
        )
        .unwrap();
        eprintln!(
            "plonky3 scan k=8192 tape×8 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }
}
