//! Plonky3 uni-STARK of [`tiny_f::tiny_f`], [`tiny_f::match_step`],
//! [`tiny_f::book_step`], [`tiny_f::book_walk`], [`tiny_f::mixed_f`],
//! [`tiny_f::scan_event`], a Poseidon2-16 path, a BLAKE3 compression
//! gadget, and resting-map `node_digest`. Packed-prefix 8k book is rows,
//! not columns. The dummy path of 20 is not `C'`. One `node_digest` is
//! the `C'` string. 19 openings (18 resting + 1 prio) is one upsert path —
//! same *count* as HeightMatch, different tape. 72 chronological openings
//! (69 node + 3 prio) is one engine Place at 8k — the native BLAKE3
//! count. 281 chronological openings (269 node + 12 prio) is eight mixed
//! events on that book — the native BLAKE3 count. Fourteen chrono map
//! hashes of the two-place `HeightStatement` height stacked with that
//! height's match-step, rest bound to the 4-block leaf and take bound to
//! `I`, last digest `post_root` of the INC transcript, is still not `F`
//! (match-step treap hashes are 0; apply is 5 prio + 9 node; HeightMatch
//! 19 ≠ 72/281/363497; NodePath also 19 = 18+1 prio, not that tape).
//! Genesis INC hashes to `pre_root`.
//! INC height/`next_time`/instruments on this fixture are bound. Parent is
//! `GENESIS_PARENT`. Settlement 277 B hashes to `settlement_commitment`.
//! Base amounts equal fill; quote amounts equal notional. Maker account
//! equals the rest leaf owner and the first Place in `I`; taker equals
//! the take Place. First Place qty/price equal match rest. First Place
//! id/instrument/side equal the rest leaf. Take Place id/instrument are
//! `from_u128(5)` / instrument 1. First Place expiry/nonce equal the rest
//! leaf. Take Place expiry/nonce equal the same constants. Rest `TimeSeq`
//! is `TimeSeq(0)`, not post `next_time`. Rest left/right children are
//! `treap_empty_digest()`. Domain / version / key_len / OrderId key /
//! value_len / `RESTING` tag are the 216 B header. Seen/nonce share
//! `TREAP_NODE_DOMAIN` / version / lens; prio share `TREAP_PRIO_DOMAIN`.
//! First key byte is 1 or 2 by `hidx`. `I` is `INPUT_DOMAIN` / version /
//! payload_len 206 / count 2 / two `INPLACE`+`ORDER` tags. Both 244 B INC
//! openings are `INC_DOMAIN` / version / `height`. Settlement is
//! `RECEIPT_DOMAIN` / version / payload_len 248 / count 4 / four `DELTA` tags.
//! Post INC map tags are `nonces` / `seenid` / `books` with Digest len 32.
//! Tree edges on this rotate fixture: nonce root (hidx 9) left = opening 8
//! `out`; seen rotate root (hidx 13) left = demoted opening 12 `out`, with
//! heap + BST order, demote pins, and left-overwrite (see `HeightMatchAir`).
//! Assets are
//! this fixture's base/quote.
//! Not the loaded 10k tape, not a CLOB apply license.
//!
//! [`FriClass::Test`] matches p3-uni-stark tests (`num_queries = 2`).
//! [`FriClass::Prod`] is SP1 Turbo-shaped (100 queries, 16 PoW bits,
//! official Poseidon2-16). Neither is a security proof. Neither is height `π`.
#![forbid(unsafe_code)]

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::rngs::StdRng;
use rand::SeedableRng;
use tiny_f::{TinyFError, TinyStatement, QTY_BITS};

const COL_MAKER: usize = 0;
const COL_TAKER: usize = 1;
const COL_PRICE: usize = 2;
const COL_FILL: usize = 3;
const COL_NOTIONAL: usize = 4;
const COL_DM_BITS: usize = 5;
const WIDTH: usize = 5 + (QTY_BITS as usize) * 2;
pub(crate) const TRACE_ROWS: usize = 8;

/// FRI / sponge cell. Prove and verify must use the same class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FriClass {
    /// p3-uni-stark test params. Not a soundness claim.
    Test,
    /// 100 queries, 16 PoW bits, Grain-LFSR Poseidon2-16. Still not a security proof.
    Prod,
}

impl FriClass {
    pub fn queries(self) -> usize {
        match self {
            Self::Test => 2,
            Self::Prod => 100,
        }
    }

    pub fn pow_bits(self) -> usize {
        match self {
            Self::Test => 1,
            Self::Prod => 16,
        }
    }

    pub fn official_poseidon(self) -> bool {
        matches!(self, Self::Prod)
    }
}

mod blake3_air;
mod book_air;
mod match_air;
mod mixed_air;
mod path_air;
mod scan_air;
mod walk_air;

pub use blake3_air::{
    blake3_compress, blake3_hash64, blake3_hash_msg, blake3_path, decode_height_match_pi,
    decode_height_pi, encode_height_match_pi, encode_height_pi, genesis_inc_preimage,
    input_commit_preimage, node_preimage, settlement_commit_preimage,
    prove_blake3_path_and_report_with,
    prove_blake3_path_with, prove_book_node_path_and_report_with, prove_book_node_path_with,
    prove_compress_and_report_with, prove_compress_with, prove_engine_insert_and_report_with,
    prove_engine_insert_with, prove_engine_tape_and_report_with, prove_engine_tape_with,
    mid_books_from_openings, prove_g_and_report_with, prove_g_with,
    prove_height_match_and_report_with, prove_height_match_mid, prove_height_match_with,
    prove_height_openings_and_report_with, prove_height_openings_with,
    prove_node_digest_and_report_with, prove_node_digest_with, prove_node_path_and_report_with,
    prove_node_path_with, unit_blake3_path, unit_block, unit_g, unit_resting_kv,
    unit_resting_kv_at, unit_resting_node, unit_upsert_node_path, verify_blake3_path_with,
    verify_book_node_path_with, verify_compress_with, verify_engine_insert_with,
    verify_engine_tape_with, verify_g_with, verify_height_match_mid, verify_height_match_with,
    verify_height_openings_with,
    verify_node_digest_with, verify_node_path_with, Blake3CompressAir, Blake3CompressProof,
    Blake3G, Blake3GAir, Blake3GProof, Blake3PathAir, Blake3PathProof, BookNodePathAir,
    BookNodePathProof, EngineInsertAir, EngineInsertProof, EngineTapeAir, EngineTapeProof,
    HeightMatchAir, HeightMatchProof, HeightOpeningsAir, HeightOpeningsProof, NodeDigestAir,
    NodeDigestProof, NodePathAir, NodePathProof, BLAKE3_PATH_LEN, ENGINE_INSERT_NODE_OPENINGS, ENGINE_INSERT_OPENINGS, ENGINE_INSERT_PRIO,
    ENGINE_TAPE_EVENTS, ENGINE_TAPE_NODE_OPENINGS, ENGINE_TAPE_OPENINGS, ENGINE_TAPE_PRIO, HEIGHT_MATCH_OPENINGS, HEIGHT_NODE_OPENINGS,
    HEIGHT_OPENINGS, HEIGHT_PRIO, INC_HEIGHT_OFF, INC_INSTR_OFF, INC_NEXT_T_OFF, INC_ROOT_BYTES,
    INPUT_COMMIT_BYTES, NODE_DIGEST_BLOCKS, NODE_PATH_LEN, NODE_PATH_NODE_OPENINGS, NODE_PATH_PRIO, NONCE_NODE_BYTES, NONCE_ROOT_OFF,
    PRIO_ORDER_BYTES, PRIO_OWNER_BYTES, RESTING_NODE_BYTES, REST_ROOT_OFF, SEEN_NODE_BYTES,
    SEEN_ROOT_OFF, SETTLEMENT_COMMIT_BYTES,
};
pub use book_air::{
    prove_book, prove_book_and_report, prove_book_and_report_with, prove_book_with, verify_book,
    verify_book_with, BookAir, BookProof,
};
pub use match_air::{
    prove_match, prove_match_and_report, prove_match_and_report_with, prove_match_with,
    verify_match, verify_match_with, MatchAir, MatchProof,
};
pub use mixed_air::{
    prove_mixed_and_report_with, prove_mixed_with, verify_mixed_with, MixedAir, MixedProof,
};
pub use path_air::{
    poseidon2_compress, poseidon2_path, prove_path_and_report_with, prove_path_with, unit_path,
    verify_path_with, PathAir, PathProof, PathStatement, ENGINE_INSERT_LEN, PATH_LEN,
};
pub use scan_air::{
    prove_scan_and_report_with, prove_scan_tape_and_report_with, prove_scan_with, verify_scan_with,
    ScanAir, ScanProof,
};
pub use walk_air::{
    prove_walk_and_report_with, prove_walk_with, verify_walk_with, WalkAir, WalkProof,
};

pub(crate) type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

pub struct FillAir;

impl<F> BaseAir<F> for FillAir {
    fn width(&self) -> usize {
        WIDTH
    }

    fn num_public_values(&self) -> usize {
        5
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for FillAir {
    fn eval(&self, builder: &mut AB) {
        let (p0, p1, p2, p3, p4, maker, taker, price, fill, notional) = {
            let main = builder.main();
            let pis = builder.public_values();
            (
                pis[0],
                pis[1],
                pis[2],
                pis[3],
                pis[4],
                main.current(COL_MAKER).unwrap(),
                main.current(COL_TAKER).unwrap(),
                main.current(COL_PRICE).unwrap(),
                main.current(COL_FILL).unwrap(),
                main.current(COL_NOTIONAL).unwrap(),
            )
        };

        builder.assert_eq(maker, p0);
        builder.assert_eq(taker, p1);
        builder.assert_eq(price, p2);
        builder.assert_eq(fill, p3);
        builder.assert_eq(notional, p4);

        // fill ∈ {maker, taker}
        builder.assert_zero((fill - maker) * (fill - taker));
        // notional = fill × price (fits BabyBear under the instance class)
        builder.assert_eq(fill * price, notional);

        let dm = range_sum::<AB>(builder, COL_DM_BITS);
        let dt = range_sum::<AB>(builder, COL_DM_BITS + QTY_BITS as usize);
        builder.assert_eq(maker - fill, dm);
        builder.assert_eq(taker - fill, dt);
    }
}

fn range_sum<AB: AirBuilder>(builder: &mut AB, start: usize) -> AB::Expr {
    let bits: Vec<AB::Var> = {
        let main = builder.main();
        (0..QTY_BITS as usize)
            .map(|i| main.current(start + i).unwrap())
            .collect()
    };
    let mut acc = AB::Expr::ZERO;
    let mut pow = AB::Expr::ONE;
    for b in bits {
        builder.assert_bool(b);
        acc = acc + b.into() * pow.clone();
        pow = pow.clone() + pow;
    }
    acc
}

pub(crate) fn make_config(class: FriClass) -> MyConfig {
    let perm = match class {
        FriClass::Test => {
            let mut rng = StdRng::seed_from_u64(1);
            Perm::new_from_rng_128(&mut rng)
        }
        FriClass::Prod => default_babybear_poseidon2_16(),
    };
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let pow = class.pow_bits();
    let fri_params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: class.queries(),
        commit_proof_of_work_bits: pow,
        query_proof_of_work_bits: pow,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

pub(crate) fn field(v: u64) -> Val {
    Val::from_u64(v)
}

fn public_values(stmt: &TinyStatement) -> Result<[Val; 5], TinyFError> {
    stmt.check()?;
    let n = u64::try_from(stmt.output.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
    Ok([
        field(stmt.instance.maker_qty.0),
        field(stmt.instance.taker_qty.0),
        field(stmt.instance.price.0),
        field(stmt.output.fill_qty.0),
        field(n),
    ])
}

fn generate_trace(stmt: &TinyStatement) -> Result<RowMajorMatrix<Val>, TinyFError> {
    stmt.check()?;
    let n = u64::try_from(stmt.output.notional).map_err(|_| TinyFError::OutsideInstanceClass)?;
    let mut row = vec![Val::ZERO; WIDTH];
    row[COL_MAKER] = field(stmt.instance.maker_qty.0);
    row[COL_TAKER] = field(stmt.instance.taker_qty.0);
    row[COL_PRICE] = field(stmt.instance.price.0);
    row[COL_FILL] = field(stmt.output.fill_qty.0);
    row[COL_NOTIONAL] = field(n);
    let dm = stmt.instance.maker_qty.0 - stmt.output.fill_qty.0;
    let dt = stmt.instance.taker_qty.0 - stmt.output.fill_qty.0;
    for i in 0..QTY_BITS as usize {
        row[COL_DM_BITS + i] = field((dm >> i) & 1);
        row[COL_DM_BITS + QTY_BITS as usize + i] = field((dt >> i) & 1);
    }
    let mut values = Vec::with_capacity(TRACE_ROWS * WIDTH);
    for _ in 0..TRACE_ROWS {
        values.extend_from_slice(&row);
    }
    Ok(RowMajorMatrix::new(values, WIDTH))
}

#[derive(Clone, Debug)]
pub struct TinyProof {
    pub bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error(transparent)]
    Tiny(#[from] TinyFError),
    #[error("serialize proof")]
    Serialize,
}

#[derive(Debug, thiserror::Error)]
pub enum Plonky3VerifyError {
    #[error(transparent)]
    Tiny(#[from] TinyFError),
    #[error("deserialize or verify failed")]
    Rejected,
}

#[derive(Clone, Copy, Debug)]
pub struct ProofReport {
    pub prove_ms: u128,
    pub verify_ms: u128,
    pub proof_bytes: usize,
    pub fri_queries: usize,
    pub pow_bits: usize,
    pub official_poseidon: bool,
}

impl ProofReport {
    pub(crate) fn for_class(
        class: FriClass,
        prove_ms: u128,
        verify_ms: u128,
        proof_bytes: usize,
    ) -> Self {
        Self {
            prove_ms,
            verify_ms,
            proof_bytes,
            fri_queries: class.queries(),
            pow_bits: class.pow_bits(),
            official_poseidon: class.official_poseidon(),
        }
    }
}

pub fn prove_tiny(stmt: TinyStatement) -> Result<TinyProof, ProveError> {
    prove_tiny_with(stmt, FriClass::Test)
}

pub fn prove_tiny_with(stmt: TinyStatement, class: FriClass) -> Result<TinyProof, ProveError> {
    let config = make_config(class);
    let trace = generate_trace(&stmt)?;
    let pis = public_values(&stmt)?;
    let proof = prove(&config, &FillAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(TinyProof { bytes })
}

pub fn verify_tiny(stmt: TinyStatement, proof: &TinyProof) -> Result<(), Plonky3VerifyError> {
    verify_tiny_with(stmt, proof, FriClass::Test)
}

pub fn verify_tiny_with(
    stmt: TinyStatement,
    proof: &TinyProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_values(&stmt)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &FillAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_and_report(stmt: TinyStatement) -> Result<(TinyProof, ProofReport), ProveError> {
    prove_and_report_with(stmt, FriClass::Test)
}

pub fn prove_and_report_with(
    stmt: TinyStatement,
    class: FriClass,
) -> Result<(TinyProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_tiny_with(stmt, class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_tiny_with(stmt, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{Price, Qty};
    use tiny_f::{TinyInstance, TinyStatement};

    fn stmt() -> TinyStatement {
        TinyStatement::prove_native(TinyInstance {
            maker_qty: Qty(10),
            taker_qty: Qty(7),
            price: Price(90),
        })
        .unwrap()
    }

    #[test]
    fn prove_verify_partial_fill() {
        let s = stmt();
        let (proof, report) = prove_and_report(s).unwrap();
        assert!(proof.bytes.len() > 32);
        assert_eq!(report.fri_queries, 2);
        eprintln!(
            "plonky3 tiny-F test: prove {} ms, verify {} ms, {} bytes, FRI queries {}",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_verify_partial_fill_prod() {
        let s = stmt();
        let (proof, report) = prove_and_report_with(s, FriClass::Prod).unwrap();
        assert!(proof.bytes.len() > 32);
        assert_eq!(report.fri_queries, 100);
        assert!(report.official_poseidon);
        eprintln!(
            "plonky3 tiny-F prod: prove {} ms, verify {} ms, {} bytes, FRI queries {}, PoW {}",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[test]
    fn equal_qty_also_proves() {
        let s = TinyStatement::prove_native(TinyInstance {
            maker_qty: Qty(10),
            taker_qty: Qty(10),
            price: Price(90),
        })
        .unwrap();
        let proof = prove_tiny(s).unwrap();
        verify_tiny(s, &proof).unwrap();
    }

    #[test]
    fn different_statement_rejected() {
        let s = stmt();
        let proof = prove_tiny(s).unwrap();
        let other = TinyStatement::prove_native(TinyInstance {
            maker_qty: Qty(10),
            taker_qty: Qty(10),
            price: Price(90),
        })
        .unwrap();
        assert!(verify_tiny(other, &proof).is_err());
    }
}
