//! BLAKE3 G-function, one-compression, dummy path, and `node_digest` AIRs.
//! 32-bit ARX on 16-bit BabyBear limbs.
//!
//! Resting-map `node_digest` is a **4-block** chunk (216 B), CV-chained,
//! last flags `CHUNK_END|ROOT`. An 8k upsert is **18** of those in one
//! STARK. Engine Place at 8k is **72** chronological openings = **69** node
//! (seen 115 B / 2-block, nonce 139 B / 3-block, resting 216 B / 4-block)
//! + **3** prio (49 B / 33 B / 33 B, 1-block) interleaved via
//! `start_c_prime_trace`. Eight mixed events are **281** = **269** node +
//! **12** prio (chrono). One resting upsert is **19** chrono = **18** node +
//! **1** prio (same count as HeightMatch, different tape). Full native
//! `C'` hash counts, not `F`. Portable `g` lockstep.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove, verify};

use crate::book_air::{book_public_values, eval_book, generate_book_row, BOOK_PIS, BOOK_WIDTH};
use crate::match_air::{
    eval_match, generate_match_row, match_public_values, MATCH_PIS, MATCH_WIDTH,
};
use crate::{field, make_config, FriClass, Plonky3VerifyError, ProofReport, ProveError, Val};

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];
const CHUNK_START: u8 = 1;
const CHUNK_END: u8 = 2;
const ROOT: u8 = 8;
const LIMB: u32 = 1 << 16;
const BITS: usize = 32;
const TRACE_ROWS: usize = 8;

const COL_A: usize = 0;
const COL_B: usize = 2;
const COL_C: usize = 4;
const COL_D: usize = 6;
const COL_X: usize = 8;
const COL_Y: usize = 10;
const COL_AO: usize = 12;
const COL_BO: usize = 14;
const COL_CO: usize = 16;
const COL_DO: usize = 18;
const COL_AB: usize = 20;
const COL_A1: usize = 22;
const COL_D1: usize = 24;
const COL_C1: usize = 26;
const COL_B1: usize = 28;
const COL_A1B: usize = 30;
const COL_A2: usize = 32;
const COL_D2: usize = 34;
const COL_C2: usize = 36;
const COL_B2: usize = 38;
const COL_CARRY: usize = 40;
const N_CARRY: usize = 12;
const COL_BITS: usize = COL_CARRY + N_CARRY;
const G_AB: usize = 0;
const G_A1: usize = 1;
const G_D: usize = 2;
const G_DX: usize = 3;
const G_D1: usize = 4;
const G_C1: usize = 5;
const G_B: usize = 6;
const G_BX: usize = 7;
const G_B1: usize = 8;
const G_A1B: usize = 9;
const G_A2: usize = 10;
const G_D2X: usize = 11;
const G_D2: usize = 12;
const G_C2: usize = 13;
const G_B2X: usize = 14;
const G_B2: usize = 15;
const NG: usize = 16;
const WIDTH: usize = COL_BITS + NG * BITS;
const PIS: usize = 20;
const G_IDX: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];
const COL_S: usize = WIDTH;
const COL_SO: usize = COL_S + 32;
const COL_GI: usize = COL_SO + 32;
const COL_RND: usize = COL_GI + 8;
const COL_KG: usize = COL_RND + 7;
const COL_KO: usize = COL_KG + 1;
const COL_OI: usize = COL_KO + 1;
const COL_STEPR: usize = COL_OI + 8;
const COL_LASTG: usize = COL_STEPR + 1;
const COL_MSG: usize = COL_LASTG + 1;
const COL_MSCH: usize = COL_MSG + 32;
const COL_XL: usize = COL_MSCH + 32;
const COL_XR: usize = COL_XL + 2;
const COL_XX: usize = COL_XR + 2;
const COL_XBITS: usize = COL_XX + 2;
const C_WIDTH: usize = COL_XBITS + BITS * 3;
const C_PIS: usize = 48;
const C_ROWS: usize = 64;
const N_G: usize = 56;
pub const BLAKE3_PATH_LEN: usize = 20;
const COL_H: usize = C_WIDTH;
const COL_PAD: usize = COL_H + BLAKE3_PATH_LEN;
const COL_SIB: usize = COL_PAD + 1;
const COL_DIG: usize = COL_SIB + 16;
const COL_ENDH: usize = COL_DIG + 16;
const COL_WRAPH: usize = COL_ENDH + 1;
const COL_ROOTCHK: usize = COL_WRAPH + 1;
const COL_DIGO: usize = COL_ROOTCHK + 1;
const P_WIDTH: usize = COL_DIGO + 16;
const P_PIS: usize = 32;
const P_ROWS: usize = 2048;
const P_ACTIVE: usize = BLAKE3_PATH_LEN * C_ROWS;
pub const NODE_DIGEST_BLOCKS: usize = 4;
const COL_NB: usize = C_WIDTH;
const COL_ENDN: usize = COL_NB + NODE_DIGEST_BLOCKS;
const COL_WRAPN: usize = COL_ENDN + 1;
const COL_ROOTN: usize = COL_WRAPN + 1;
const COL_NCV: usize = COL_ROOTN + 1;
const COL_NCVO: usize = COL_NCV + 16;
const COL_NMSG: usize = COL_NCVO + 16;
const N_WIDTH: usize = COL_NMSG + 32;
const N_PIS: usize = 64 * 2 + 16;
const N_ROWS: usize = NODE_DIGEST_BLOCKS * C_ROWS;
pub const RESTING_NODE_BYTES: usize = 216;
/// 8k resting upsert: 18 `node_digest` + 1 OrderId prio = native 19 BLAKE3s.
/// Same *count* as HeightMatch (19), different tape (not I/INC/settlement/match).
pub const NODE_PATH_NODE_OPENINGS: usize = 18;
pub const NODE_PATH_PRIO: usize = 1;
pub const NODE_PATH_LEN: usize = NODE_PATH_NODE_OPENINGS + NODE_PATH_PRIO;
const NP_PIS: usize = 16;
const NP_ROWS: usize = 8192;
pub const SEEN_NODE_BYTES: usize = 115;
pub const NONCE_NODE_BYTES: usize = 139;
/// Place-at-8k: 69 `node_digest` + 3 prio = native 72 BLAKE3s. Not HeightMatch.
pub const ENGINE_INSERT_NODE_OPENINGS: usize = 69;
pub const ENGINE_INSERT_PRIO: usize = 3;
pub const ENGINE_INSERT_OPENINGS: usize = ENGINE_INSERT_NODE_OPENINGS + ENGINE_INSERT_PRIO;
const COL_BLAST: usize = N_WIDTH;
const COL_BLEN: usize = COL_BLAST + 1;
const COL_BFLG: usize = COL_BLEN + 1;
const COL_EH: usize = COL_BFLG + 1;
const COL_EPAD: usize = COL_EH + ENGINE_INSERT_OPENINGS;
const COL_EWRAP: usize = COL_EPAD + 1;
const COL_EROOT: usize = COL_EWRAP + 1;
const COL_EPRE: usize = COL_EROOT + 1;
/// 1-block prio selectors (OrderId 33 B / OwnerId 49 B).
const COL_EQ33: usize = COL_EPRE + 128;
const COL_EQ49: usize = COL_EQ33 + 1;
/// Insert keys: order prio (hidx 4) → seen 5 / rest 39 (2 key bytes);
/// owner prio (hidx 0) → nonce 1; second order prio 38; nonce twin 3;
/// rest owner → LAT_OWN. Not HeightMatch; not `F`.
const COL_EI_LOAD_OID: usize = COL_EQ49 + 1;
const COL_EI_LAT_OID0: usize = COL_EI_LOAD_OID + 1;
const COL_EI_LAT_OID1: usize = COL_EI_LAT_OID0 + 1;
const COL_EI_LOAD_OWN: usize = COL_EI_LAT_OID1 + 1;
const COL_EI_LAT_OWN0: usize = COL_EI_LOAD_OWN + 1;
/// `q33 ∧ h[38] ∧ rootn` — second OrderId prio matches latched oid.
const COL_EI_CHK_OID2: usize = COL_EI_LAT_OWN0 + 1;
/// Nonce rotate: latch opening 2 `out` → left child of opening 3.
const COL_EI_LOAD_N2: usize = COL_EI_CHK_OID2 + 1;
const COL_EI_LAT_N2: usize = COL_EI_LOAD_N2 + 1;
const COL_EI_N2BIT: usize = COL_EI_LAT_N2 + 16;
/// Sibling fan-outs: rights out(6/40/12/46/20/54/24/58); lefts …/18/52/22/56/26/60.
const COL_EI_LOAD_S6: usize = COL_EI_N2BIT + 256;
const COL_EI_LAT_S6: usize = COL_EI_LOAD_S6 + 1;
const COL_EI_S6BIT: usize = COL_EI_LAT_S6 + 16;
const COL_EI_LOAD_R40: usize = COL_EI_S6BIT + 256;
const COL_EI_LAT_R40: usize = COL_EI_LOAD_R40 + 1;
const COL_EI_LOAD_S8: usize = COL_EI_LAT_R40 + 16;
const COL_EI_LAT_S8: usize = COL_EI_LOAD_S8 + 1;
const COL_EI_S8BIT: usize = COL_EI_LAT_S8 + 16;
const COL_EI_LOAD_R42: usize = COL_EI_S8BIT + 256;
const COL_EI_LAT_R42: usize = COL_EI_LOAD_R42 + 1;
const COL_EI_R42BIT: usize = COL_EI_LAT_R42 + 16;
const COL_EI_LOAD_S10: usize = COL_EI_R42BIT + 256;
const COL_EI_LAT_S10: usize = COL_EI_LOAD_S10 + 1;
const COL_EI_S10BIT: usize = COL_EI_LAT_S10 + 16;
const COL_EI_LOAD_R44: usize = COL_EI_S10BIT + 256;
const COL_EI_LAT_R44: usize = COL_EI_LOAD_R44 + 1;
const COL_EI_R44BIT: usize = COL_EI_LAT_R44 + 16;
const COL_EI_LOAD_S12: usize = COL_EI_R44BIT + 256;
const COL_EI_LAT_S12: usize = COL_EI_LOAD_S12 + 1;
const COL_EI_S12BIT: usize = COL_EI_LAT_S12 + 16;
const COL_EI_LOAD_R46: usize = COL_EI_S12BIT + 256;
const COL_EI_LAT_R46: usize = COL_EI_LOAD_R46 + 1;
const COL_EI_LOAD_S14: usize = COL_EI_LAT_R46 + 16;
const COL_EI_LAT_S14: usize = COL_EI_LOAD_S14 + 1;
const COL_EI_S14BIT: usize = COL_EI_LAT_S14 + 16;
const COL_EI_LOAD_R48: usize = COL_EI_S14BIT + 256;
const COL_EI_LAT_R48: usize = COL_EI_LOAD_R48 + 1;
const COL_EI_R48BIT: usize = COL_EI_LAT_R48 + 16;
const COL_EI_LOAD_S16: usize = COL_EI_R48BIT + 256;
const COL_EI_LAT_S16: usize = COL_EI_LOAD_S16 + 1;
const COL_EI_S16BIT: usize = COL_EI_LAT_S16 + 16;
const COL_EI_LOAD_R50: usize = COL_EI_S16BIT + 256;
const COL_EI_LAT_R50: usize = COL_EI_LOAD_R50 + 1;
const COL_EI_R50BIT: usize = COL_EI_LAT_R50 + 16;
const COL_EI_LOAD_S18: usize = COL_EI_R50BIT + 256;
const COL_EI_LAT_S18: usize = COL_EI_LOAD_S18 + 1;
const COL_EI_S18BIT: usize = COL_EI_LAT_S18 + 16;
const COL_EI_LOAD_R52: usize = COL_EI_S18BIT + 256;
const COL_EI_LAT_R52: usize = COL_EI_LOAD_R52 + 1;
const COL_EI_R52BIT: usize = COL_EI_LAT_R52 + 16;
const COL_EI_LOAD_S20: usize = COL_EI_R52BIT + 256;
const COL_EI_LAT_S20: usize = COL_EI_LOAD_S20 + 1;
const COL_EI_S20BIT: usize = COL_EI_LAT_S20 + 16;
const COL_EI_LOAD_R54: usize = COL_EI_S20BIT + 256;
const COL_EI_LAT_R54: usize = COL_EI_LOAD_R54 + 1;
const COL_EI_LOAD_S22: usize = COL_EI_LAT_R54 + 16;
const COL_EI_LAT_S22: usize = COL_EI_LOAD_S22 + 1;
const COL_EI_S22BIT: usize = COL_EI_LAT_S22 + 16;
const COL_EI_LOAD_R56: usize = COL_EI_S22BIT + 256;
const COL_EI_LAT_R56: usize = COL_EI_LOAD_R56 + 1;
const COL_EI_R56BIT: usize = COL_EI_LAT_R56 + 16;
const COL_EI_LOAD_S24: usize = COL_EI_R56BIT + 256;
const COL_EI_LAT_S24: usize = COL_EI_LOAD_S24 + 1;
const COL_EI_S24BIT: usize = COL_EI_LAT_S24 + 16;
const COL_EI_LOAD_R58: usize = COL_EI_S24BIT + 256;
const COL_EI_LAT_R58: usize = COL_EI_LOAD_R58 + 1;
const COL_EI_LOAD_S26: usize = COL_EI_LAT_R58 + 16;
const COL_EI_LAT_S26: usize = COL_EI_LOAD_S26 + 1;
const COL_EI_S26BIT: usize = COL_EI_LAT_S26 + 16;
const COL_EI_LOAD_R60: usize = COL_EI_S26BIT + 256;
const COL_EI_LAT_R60: usize = COL_EI_LOAD_R60 + 1;
const COL_EI_R60BIT: usize = COL_EI_LAT_R60 + 16;
const EI_WIDTH: usize = COL_EI_R60BIT + 256;
const EI_HIDX_OWNER_PRIO: usize = 0;
const EI_HIDX_NONCE0: usize = 1;
const EI_HIDX_NONCE_MID: usize = 2;
const EI_HIDX_NONCE1: usize = 3;
const EI_HIDX_ORDER_PRIO: usize = 4;
const EI_HIDX_ORDER_PRIO2: usize = 38;
const EI_HIDX_SEEN_SIB0: usize = 6;
const EI_HIDX_REST_SIB0: usize = 40;
const EI_HIDX_SEEN_SIB1: usize = 8;
const EI_HIDX_REST_SIB1: usize = 42;
const EI_HIDX_SEEN_SIB2: usize = 10;
const EI_HIDX_REST_SIB2: usize = 44;
const EI_HIDX_SEEN_SIB3: usize = 12;
const EI_HIDX_REST_SIB3: usize = 46;
const EI_HIDX_SEEN_SIB4: usize = 14;
const EI_HIDX_REST_SIB4: usize = 48;
const EI_HIDX_SEEN_SIB5: usize = 16;
const EI_HIDX_REST_SIB5: usize = 50;
const EI_HIDX_SEEN_SIB6: usize = 18;
const EI_HIDX_REST_SIB6: usize = 52;
const EI_HIDX_SEEN_SIB7: usize = 20;
const EI_HIDX_REST_SIB7: usize = 54;
const EI_HIDX_SEEN_SIB8: usize = 22;
const EI_HIDX_REST_SIB8: usize = 56;
const EI_HIDX_SEEN_SIB9: usize = 24;
const EI_HIDX_REST_SIB9: usize = 58;
const EI_HIDX_SEEN_SIB10: usize = 26;
const EI_HIDX_REST_SIB10: usize = 60;
/// Insert-path seen/rest openings whose OrderId equals the latched oid (fixture).
const EI_SEEN_OID_PATH: [usize; 12] = [5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27];
const EI_REST_OID_PATH: [usize; 12] = [39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61];
/// Path openings whose right child is out(6) / out(40) (fixture first fan-out).
const EI_SEEN_RIGHT_FROM_SIB0: [usize; 3] = [7, 9, 11];
const EI_REST_RIGHT_FROM_SIB0: [usize; 3] = [41, 43, 45];
/// Path openings whose left child is out(8) / out(42) (completes path[1] nodes).
const EI_SEEN_LEFT_FROM_SIB1: [usize; 1] = [9];
const EI_REST_LEFT_FROM_SIB1: [usize; 1] = [43];
/// Path openings whose left child is out(10) / out(44).
const EI_SEEN_LEFT_FROM_SIB2: [usize; 2] = [11, 13];
const EI_REST_LEFT_FROM_SIB2: [usize; 2] = [45, 47];
/// Path openings whose right child is out(12) / out(46).
const EI_SEEN_RIGHT_FROM_SIB3: [usize; 4] = [13, 15, 17, 19];
const EI_REST_RIGHT_FROM_SIB3: [usize; 4] = [47, 49, 51, 53];
/// Path openings whose left child is out(14) / out(48).
const EI_SEEN_LEFT_FROM_SIB4: [usize; 1] = [15];
const EI_REST_LEFT_FROM_SIB4: [usize; 1] = [49];
/// Path openings whose left child is out(16) / out(50).
const EI_SEEN_LEFT_FROM_SIB5: [usize; 1] = [17];
const EI_REST_LEFT_FROM_SIB5: [usize; 1] = [51];
/// Path openings whose left child is out(18) / out(52).
const EI_SEEN_LEFT_FROM_SIB6: [usize; 2] = [19, 21];
const EI_REST_LEFT_FROM_SIB6: [usize; 2] = [53, 55];
/// Path openings whose right child is out(20) / out(54).
const EI_SEEN_RIGHT_FROM_SIB7: [usize; 2] = [21, 23];
const EI_REST_RIGHT_FROM_SIB7: [usize; 2] = [55, 57];
/// Path openings whose left child is out(22) / out(56).
const EI_SEEN_LEFT_FROM_SIB8: [usize; 2] = [23, 25];
const EI_REST_LEFT_FROM_SIB8: [usize; 2] = [57, 59];
/// Path openings whose right child is out(24) / out(58).
const EI_SEEN_RIGHT_FROM_SIB9: [usize; 2] = [25, 27];
const EI_REST_RIGHT_FROM_SIB9: [usize; 2] = [59, 61];
/// Path openings whose left child is out(26) / out(60) (last insert-path sibling).
const EI_SEEN_LEFT_FROM_SIB10: [usize; 1] = [27];
const EI_REST_LEFT_FROM_SIB10: [usize; 1] = [61];
const EI_PIS: usize = 16;
const EI_ROWS: usize = 16384;
pub const ENGINE_TAPE_EVENTS: usize = 8;
/// Eight mixed events at 8k: 269 `node_digest` + 12 prio = native 281 BLAKE3s
/// (chronological via `start_c_prime_trace`).
pub const ENGINE_TAPE_NODE_OPENINGS: usize = 269;
pub const ENGINE_TAPE_PRIO: usize = 12;
pub const ENGINE_TAPE_OPENINGS: usize = ENGINE_TAPE_NODE_OPENINGS + ENGINE_TAPE_PRIO;
const COL_HIDX: usize = COL_BFLG + 1;
const COL_HLAST: usize = COL_HIDX + 1;
const COL_HINV: usize = COL_HLAST + 1;
const COL_TPAD: usize = COL_HINV + 1;
const COL_TWRAP: usize = COL_TPAD + 1;
const COL_TROOT: usize = COL_TWRAP + 1;
const COL_TPRE: usize = COL_TROOT + 1;
const T_WIDTH: usize = COL_TPRE + 128;
const T_PIS: usize = 16;
const T_ROWS: usize = 65536;
/// 1-block last-len selectors (prio). Shared by HeightMatch + EngineTape.
const COL_Q33: usize = T_WIDTH;
const COL_Q49: usize = T_WIDTH + 1;
/// 4-block last-len: resting 216 (24), `I` 233 (41), INC `C'` 244 (52).
const COL_Q24: usize = T_WIDTH + 2;
const COL_Q41: usize = T_WIDTH + 3;
const COL_Q52: usize = T_WIDTH + 4;
/// 5-block last-len: settlement receipt 277 (21). Height-only.
const COL_Q21: usize = T_WIDTH + 5;
const COL_NB4: usize = T_WIDTH + 6;
const COL_B3N: usize = T_WIDTH + 7;
const COL_TPRE5: usize = T_WIDTH + 8;
const H_WIDTH: usize = COL_TPRE5 + 32;
/// OrderId prio: `TREAP_PRIO_DOMAIN` (17) || 16. OwnerId: 17 || 32.
pub const PRIO_ORDER_BYTES: usize = 33;
pub const PRIO_OWNER_BYTES: usize = 49;
/// `Digest::from_bytes` of this height’s two-Place `I` under `INPUT_DOMAIN`.
pub const INPUT_COMMIT_BYTES: usize = 233;
/// `IncrementalState::root_preimage` of this height (`INC_DOMAIN`). Not a `node_digest`.
pub const INC_ROOT_BYTES: usize = 244;
/// `Digest::from_bytes` of this height’s four `SettlementDelta`s under `RECEIPT_DOMAIN`.
pub const SETTLEMENT_COMMIT_BYTES: usize = 277;
/// Payload offsets inside [`INC_ROOT_BYTES`]. This 2-place fixture.
pub const INC_HEIGHT_OFF: usize = 31;
pub const INC_NEXT_T_OFF: usize = 53;
pub const INC_INSTR_OFF: usize = 75;
/// Two-place rotate crossing: 9 mixed `node_digest` then 5 prio (take OrderId 5).
/// Not 72 Place-at-8k, not 281 tape, not 363497 loaded 10k, not `F`, not matching.
pub const HEIGHT_NODE_OPENINGS: usize = 9;
pub const HEIGHT_PRIO: usize = 5;
pub const HEIGHT_OPENINGS: usize = HEIGHT_NODE_OPENINGS + HEIGHT_PRIO;
/// 14 C' hashes + `I` + genesis INC (`C`) + mid INC (Place1) + settlement +
/// post INC (`C'`, last). Not `F`. **HeightMatch 19 ≠ 72 / 281 / 363497**; NodePath also 19 (18+1 prio), different tape.
pub const HEIGHT_MATCH_OPENINGS: usize = HEIGHT_OPENINGS + 5;
const HO_ROWS: usize = 2048;
/// 19 openings, ~3200 active rows.
const HM_ROWS: usize = 4096;
/// Tape indices: chrono map 0..13, then I=14, genesis=15, mid=16, settlement=17, post=18.
const HIDX_GENESIS_INC: u64 = 15;
const HIDX_MID_INC: u64 = 16;
/// Mid-apply books = resting leaf at chrono hidx 5 (fixture / ApplyWitness).
#[allow(dead_code)]
const HIDX_REST: u64 = 5;
const HIDX_SEEN_FIRST: u64 = 3;

pub struct Blake3GAir;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake3G {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub x: u32,
    pub y: u32,
}

impl Blake3G {
    pub fn apply(self) -> [u32; 4] {
        let mut s = [self.a, self.b, self.c, self.d];
        g4(&mut s, 0, 1, 2, 3, self.x, self.y);
        s
    }
}

fn g4(state: &mut [u32], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn g16(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    g4(state, a, b, c, d, x, y);
}

fn round(state: &mut [u32; 16], msg: &[u32; 16], rnd: usize) {
    let sch = MSG_SCHEDULE[rnd];
    g16(state, 0, 4, 8, 12, msg[sch[0]], msg[sch[1]]);
    g16(state, 1, 5, 9, 13, msg[sch[2]], msg[sch[3]]);
    g16(state, 2, 6, 10, 14, msg[sch[4]], msg[sch[5]]);
    g16(state, 3, 7, 11, 15, msg[sch[6]], msg[sch[7]]);
    g16(state, 0, 5, 10, 15, msg[sch[8]], msg[sch[9]]);
    g16(state, 1, 6, 11, 12, msg[sch[10]], msg[sch[11]]);
    g16(state, 2, 7, 8, 13, msg[sch[12]], msg[sch[13]]);
    g16(state, 3, 4, 9, 14, msg[sch[14]], msg[sch[15]]);
}

/// One BLAKE3 compression. `cv` is overwritten with the 8-word chaining value.
pub fn blake3_compress(
    cv: &mut [u32; 8],
    block: &[u8; 64],
    block_len: u8,
    counter: u64,
    flags: u8,
) {
    let mut words = [0u32; 16];
    for i in 0..16 {
        let j = i * 4;
        words[i] = u32::from_le_bytes(block[j..j + 4].try_into().expect("4"));
    }
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len as u32,
        flags as u32,
    ];
    for r in 0..7 {
        round(&mut state, &words, r);
    }
    for i in 0..8 {
        cv[i] = state[i] ^ state[i + 8];
    }
}

/// Single 64-byte root chunk. Locksteps `blake3::hash`.
pub fn blake3_hash64(block: [u8; 64]) -> [u8; 32] {
    let mut cv = IV;
    blake3_compress(&mut cv, &block, 64, 0, CHUNK_START | CHUNK_END | ROOT);
    cv_bytes(cv)
}

pub fn unit_g() -> Blake3G {
    Blake3G {
        a: 0x1111_2222,
        b: 0x3333_4444,
        c: 0x5555_6666,
        d: 0x7777_8888,
        x: 0x9999_aaaa,
        y: 0xbbbb_cccc,
    }
}

pub fn blake3_path(leaf: [u8; 32], siblings: &[[u8; 32]]) -> [u8; 32] {
    let mut d = leaf;
    for sib in siblings {
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(&d);
        block[32..].copy_from_slice(sib);
        d = blake3_hash64(block);
    }
    d
}

pub fn unit_blake3_path(n: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    let mut leaf = [0u8; 32];
    for (i, b) in leaf.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let sibs = (0..n)
        .map(|h| {
            let mut s = [0u8; 32];
            for (j, b) in s.iter_mut().enumerate() {
                *b = (100 + h + j) as u8;
            }
            s
        })
        .collect();
    (leaf, sibs)
}

pub fn unit_block() -> [u8; 64] {
    let mut b = [0u8; 64];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = i as u8;
    }
    b
}

fn lo(w: u32) -> u32 {
    w & (LIMB - 1)
}
fn hi(w: u32) -> u32 {
    w >> 16
}

impl<F> BaseAir<F> for Blake3GAir {
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

impl<AB: AirBuilder<F = Val>> Air<AB> for Blake3GAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..WIDTH).map(|i| main.current(i).unwrap()).collect();
            (pis, cur)
        };

        for i in 0..PIS {
            builder.assert_eq(cur[i], pis[i]);
        }
        eval_g(builder, &cur);
    }
}

fn eval_g<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    for i in 0..N_CARRY {
        builder.assert_bool(cur[COL_CARRY + i]);
    }

    let abb = bits::<AB>(builder, cur, G_AB);
    let a1b = bits::<AB>(builder, cur, G_A1);
    let db = bits::<AB>(builder, cur, G_D);
    let dx = bits::<AB>(builder, cur, G_DX);
    let d1b = bits::<AB>(builder, cur, G_D1);
    let c1b = bits::<AB>(builder, cur, G_C1);
    let bb = bits::<AB>(builder, cur, G_B);
    let bx = bits::<AB>(builder, cur, G_BX);
    let b1b = bits::<AB>(builder, cur, G_B1);
    let a1bb = bits::<AB>(builder, cur, G_A1B);
    let a2b = bits::<AB>(builder, cur, G_A2);
    let d2x = bits::<AB>(builder, cur, G_D2X);
    let d2b = bits::<AB>(builder, cur, G_D2);
    let c2b = bits::<AB>(builder, cur, G_C2);
    let b2x = bits::<AB>(builder, cur, G_B2X);
    let b2b = bits::<AB>(builder, cur, G_B2);

    pack_limbs(builder, cur, COL_AB, &abb);
    pack_limbs(builder, cur, COL_A1, &a1b);
    pack_limbs(builder, cur, COL_D, &db);
    pack_limbs(builder, cur, COL_D1, &d1b);
    pack_limbs(builder, cur, COL_C1, &c1b);
    pack_limbs(builder, cur, COL_B, &bb);
    pack_limbs(builder, cur, COL_B1, &b1b);
    pack_limbs(builder, cur, COL_A1B, &a1bb);
    pack_limbs(builder, cur, COL_A2, &a2b);
    pack_limbs(builder, cur, COL_D2, &d2b);
    pack_limbs(builder, cur, COL_C2, &c2b);
    pack_limbs(builder, cur, COL_B2, &b2b);

    add2(builder, cur, COL_A, COL_B, COL_AB, COL_CARRY, COL_CARRY + 1);
    add2(
        builder,
        cur,
        COL_AB,
        COL_X,
        COL_A1,
        COL_CARRY + 2,
        COL_CARRY + 3,
    );
    xor_rotr(builder, &db, &a1b, &dx, &d1b, 16);
    add2(
        builder,
        cur,
        COL_C,
        COL_D1,
        COL_C1,
        COL_CARRY + 4,
        COL_CARRY + 5,
    );
    xor_rotr(builder, &bb, &c1b, &bx, &b1b, 12);
    add2(
        builder,
        cur,
        COL_A1,
        COL_B1,
        COL_A1B,
        COL_CARRY + 6,
        COL_CARRY + 7,
    );
    add2(
        builder,
        cur,
        COL_A1B,
        COL_Y,
        COL_A2,
        COL_CARRY + 8,
        COL_CARRY + 9,
    );
    xor_rotr(builder, &d1b, &a2b, &d2x, &d2b, 8);
    add2(
        builder,
        cur,
        COL_C1,
        COL_D2,
        COL_C2,
        COL_CARRY + 10,
        COL_CARRY + 11,
    );
    xor_rotr(builder, &b1b, &c2b, &b2x, &b2b, 7);

    builder.assert_eq(cur[COL_AO], cur[COL_A2]);
    builder.assert_eq(cur[COL_AO + 1], cur[COL_A2 + 1]);
    builder.assert_eq(cur[COL_BO], cur[COL_B2]);
    builder.assert_eq(cur[COL_BO + 1], cur[COL_B2 + 1]);
    builder.assert_eq(cur[COL_CO], cur[COL_C2]);
    builder.assert_eq(cur[COL_CO + 1], cur[COL_C2 + 1]);
    builder.assert_eq(cur[COL_DO], cur[COL_D2]);
    builder.assert_eq(cur[COL_DO + 1], cur[COL_D2 + 1]);
}

fn bits<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    group: usize,
) -> [AB::Var; BITS] {
    let start = COL_BITS + group * BITS;
    let out = std::array::from_fn(|i| cur[start + i]);
    for b in out {
        builder.assert_bool(b);
    }
    out
}

fn pack_limbs<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    limb_col: usize,
    bits: &[AB::Var; BITS],
) {
    let mut lo = AB::Expr::ZERO;
    let mut hi = AB::Expr::ZERO;
    let mut p = AB::Expr::ONE;
    for i in 0..16 {
        lo = lo + bits[i] * p.clone();
        p = p.clone() + p;
    }
    p = AB::Expr::ONE;
    for i in 0..16 {
        hi = hi + bits[16 + i] * p.clone();
        p = p.clone() + p;
    }
    builder.assert_eq(cur[limb_col], lo);
    builder.assert_eq(cur[limb_col + 1], hi);
}

fn add2<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    a: usize,
    b: usize,
    o: usize,
    c0: usize,
    c1: usize,
) {
    let two16 = AB::Expr::from(field(LIMB as u64));
    builder.assert_eq(cur[a] + cur[b], cur[o] + cur[c0] * two16.clone());
    builder.assert_eq(
        cur[a + 1] + cur[b + 1] + cur[c0],
        cur[o + 1] + cur[c1] * two16,
    );
}

fn xor_rotr<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    x: &[AB::Var; BITS],
    y: &[AB::Var; BITS],
    xor_bits: &[AB::Var; BITS],
    rot_bits: &[AB::Var; BITS],
    rot: usize,
) {
    for i in 0..BITS {
        builder.assert_eq(
            xor_bits[i],
            x[i] + y[i] - AB::Expr::from(field(2)) * x[i] * y[i],
        );
        builder.assert_eq(rot_bits[i], xor_bits[(i + rot) % BITS]);
    }
}

fn put_limbs(row: &mut [Val], col: usize, w: u32) {
    row[col] = field(lo(w) as u64);
    row[col + 1] = field(hi(w) as u64);
}

fn put_bits(row: &mut [Val], group: usize, w: u32) {
    let start = COL_BITS + group * BITS;
    for i in 0..BITS {
        row[start + i] = field(((w >> i) & 1) as u64);
    }
}

fn add_limbs(a: u32, b: u32) -> (u32, u32, u32) {
    let s = a as u64 + b as u64;
    let o = (s as u32) & u32::MAX;
    let c0 = if (a & (LIMB - 1)) as u64 + (b & (LIMB - 1)) as u64 >= LIMB as u64 {
        1
    } else {
        0
    };
    let c1 = if s >= (1u64 << 32) { 1 } else { 0 };
    (o, c0, c1)
}

fn fill_g_columns(row: &mut [Val], g: Blake3G) {
    let [ao, bo, co, d_out] = g.apply();
    let ab = g.a.wrapping_add(g.b);
    let a1 = ab.wrapping_add(g.x);
    let d1 = (g.d ^ a1).rotate_right(16);
    let c1 = g.c.wrapping_add(d1);
    let b1 = (g.b ^ c1).rotate_right(12);
    let a1b = a1.wrapping_add(b1);
    let a2 = a1b.wrapping_add(g.y);
    let d2 = (d1 ^ a2).rotate_right(8);
    let c2 = c1.wrapping_add(d2);
    let b2 = (b1 ^ c2).rotate_right(7);
    debug_assert_eq!([a2, b2, c2, d2], [ao, bo, co, d_out]);

    put_limbs(row, COL_A, g.a);
    put_limbs(row, COL_B, g.b);
    put_limbs(row, COL_C, g.c);
    put_limbs(row, COL_D, g.d);
    put_limbs(row, COL_X, g.x);
    put_limbs(row, COL_Y, g.y);
    put_limbs(row, COL_AO, ao);
    put_limbs(row, COL_BO, bo);
    put_limbs(row, COL_CO, co);
    put_limbs(row, COL_DO, d_out);
    put_limbs(row, COL_AB, ab);
    put_limbs(row, COL_A1, a1);
    put_limbs(row, COL_D1, d1);
    put_limbs(row, COL_C1, c1);
    put_limbs(row, COL_B1, b1);
    put_limbs(row, COL_A1B, a1b);
    put_limbs(row, COL_A2, a2);
    put_limbs(row, COL_D2, d2);
    put_limbs(row, COL_C2, c2);
    put_limbs(row, COL_B2, b2);

    let (_, ab_c0, ab_c1) = add_limbs(g.a, g.b);
    let (_, a1_c0, a1_c1) = add_limbs(ab, g.x);
    let (_, c1_c0, c1_c1) = add_limbs(g.c, d1);
    let (_, a1b_c0, a1b_c1) = add_limbs(a1, b1);
    let (_, a2_c0, a2_c1) = add_limbs(a1b, g.y);
    let (_, c2_c0, c2_c1) = add_limbs(c1, d2);
    row[COL_CARRY] = field(ab_c0 as u64);
    row[COL_CARRY + 1] = field(ab_c1 as u64);
    row[COL_CARRY + 2] = field(a1_c0 as u64);
    row[COL_CARRY + 3] = field(a1_c1 as u64);
    row[COL_CARRY + 4] = field(c1_c0 as u64);
    row[COL_CARRY + 5] = field(c1_c1 as u64);
    row[COL_CARRY + 6] = field(a1b_c0 as u64);
    row[COL_CARRY + 7] = field(a1b_c1 as u64);
    row[COL_CARRY + 8] = field(a2_c0 as u64);
    row[COL_CARRY + 9] = field(a2_c1 as u64);
    row[COL_CARRY + 10] = field(c2_c0 as u64);
    row[COL_CARRY + 11] = field(c2_c1 as u64);

    put_bits(row, G_AB, ab);
    put_bits(row, G_A1, a1);
    put_bits(row, G_D, g.d);
    put_bits(row, G_DX, g.d ^ a1);
    put_bits(row, G_D1, d1);
    put_bits(row, G_C1, c1);
    put_bits(row, G_B, g.b);
    put_bits(row, G_BX, g.b ^ c1);
    put_bits(row, G_B1, b1);
    put_bits(row, G_A1B, a1b);
    put_bits(row, G_A2, a2);
    put_bits(row, G_D2X, d1 ^ a2);
    put_bits(row, G_D2, d2);
    put_bits(row, G_C2, c2);
    put_bits(row, G_B2X, b1 ^ c2);
    put_bits(row, G_B2, b2);
}

fn generate_g_trace(g: Blake3G) -> RowMajorMatrix<Val> {
    let mut row = vec![Val::ZERO; WIDTH];
    fill_g_columns(&mut row, g);
    let mut values = Vec::with_capacity(TRACE_ROWS * WIDTH);
    for _ in 0..TRACE_ROWS {
        values.extend_from_slice(&row);
    }
    RowMajorMatrix::new(values, WIDTH)
}

fn public_g(g: Blake3G) -> [Val; PIS] {
    let [ao, bo, co, d_out] = g.apply();
    let words = [g.a, g.b, g.c, g.d, g.x, g.y, ao, bo, co, d_out];
    let mut pis = [Val::ZERO; PIS];
    for (i, w) in words.iter().enumerate() {
        pis[i * 2] = field(lo(*w) as u64);
        pis[i * 2 + 1] = field(hi(*w) as u64);
    }
    pis
}

#[derive(Clone, Debug)]
pub struct Blake3GProof {
    pub bytes: Vec<u8>,
}

pub fn prove_g_with(g: Blake3G, class: FriClass) -> Result<Blake3GProof, ProveError> {
    let config = make_config(class);
    let trace = generate_g_trace(g);
    let pis = public_g(g);
    let proof = prove(&config, &Blake3GAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(Blake3GProof { bytes })
}

pub fn verify_g_with(
    g: Blake3G,
    proof: &Blake3GProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_g(g);
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &Blake3GAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_g_and_report_with(
    g: Blake3G,
    class: FriClass,
) -> Result<(Blake3GProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_g_with(g, class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_g_with(g, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

pub struct Blake3CompressAir;

fn block_words(block: &[u8; 64]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for i in 0..16 {
        let j = i * 4;
        words[i] = u32::from_le_bytes(block[j..j + 4].try_into().expect("4"));
    }
    words
}

fn init_block_state(cv: [u32; 8], block_len: u8, flags: u8) -> [u32; 16] {
    [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        0,
        0,
        block_len as u32,
        flags as u32,
    ]
}

fn init_state() -> [u32; 16] {
    init_block_state(IV, 64, CHUNK_START | CHUNK_END | ROOT)
}

fn cv_bytes(cv: [u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in cv.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// BLAKE3 of one chunk (`msg.len() ≤ 1024`). Locksteps `blake3::hash`.
pub fn blake3_hash_msg(msg: &[u8]) -> [u8; 32] {
    assert!(!msg.is_empty() && msg.len() <= 1024);
    let mut cv = IV;
    let nblocks = msg.len().div_ceil(64);
    for i in 0..nblocks {
        let start = i * 64;
        let blen = (msg.len() - start).min(64) as u8;
        let mut block = [0u8; 64];
        block[..blen as usize].copy_from_slice(&msg[start..start + blen as usize]);
        let mut flags = 0u8;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i + 1 == nblocks {
            flags |= CHUNK_END | ROOT;
        }
        blake3_compress(&mut cv, &block, blen, 0, flags);
    }
    cv_bytes(cv)
}

/// ADR 0013 `node_digest` preimage. Not a STARK.
pub fn node_preimage(left: [u8; 32], key: &[u8], value: &[u8], right: [u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(99 + key.len() + value.len());
    m.extend_from_slice(commitments::TREAP_NODE_DOMAIN);
    m.extend_from_slice(&protocol_types::ENCODING_VERSION.to_le_bytes());
    m.extend_from_slice(&left);
    m.extend_from_slice(&(key.len() as u64).to_le_bytes());
    m.extend_from_slice(key);
    m.extend_from_slice(&(value.len() as u64).to_le_bytes());
    m.extend_from_slice(value);
    m.extend_from_slice(&right);
    m
}

/// Resting-map key (`OrderId` 16 B) and `RestingOrder::leaf_bytes` (101 B).
pub fn unit_resting_kv() -> (Vec<u8>, Vec<u8>) {
    unit_resting_kv_at(1)
}

pub fn unit_resting_kv_at(id: u128) -> (Vec<u8>, Vec<u8>) {
    use protocol_types::{
        CanonicalEncode, EncodeBuf, Height, InstrumentId, OrderId, OwnerId, Price, Qty, Side,
        TimeSeq,
    };
    let oid = OrderId::from_u128(id);
    let mut buf = EncodeBuf::new();
    buf.tag(*b"RESTING\0");
    oid.encode(&mut buf);
    InstrumentId(1).encode(&mut buf);
    Side::Sell.encode(&mut buf);
    Qty(10).encode(&mut buf);
    Price(90).encode(&mut buf);
    OwnerId::from_byte(1).encode(&mut buf);
    Height(1).encode(&mut buf);
    buf.u64(0);
    TimeSeq(0).encode(&mut buf);
    (oid.encode_vec(), buf.into_vec())
}

/// One-path upsert at 8k: 18 resting `node_digest` + 1 OrderId prio,
/// chronological via `start_c_prime_trace`. Same count as HeightMatch (19);
/// not that tape; not `F`.
pub fn unit_upsert_node_path() -> Vec<Vec<u8>> {
    let mut m = commitments::HashedMap::with_hash(commitments::TreapHash::Blake3);
    for i in 0..8_000u128 {
        let (k, v) = unit_resting_kv_at(i);
        m.upsert(&k, &v);
    }
    commitments::start_c_prime_trace();
    let (k, v) = unit_resting_kv_at(8_000);
    m.upsert(&k, &v);
    commitments::take_c_prime_trace()
}

pub fn unit_resting_node() -> (Vec<u8>, [u8; 32]) {
    let (key, value) = unit_resting_kv();
    let empty = commitments::treap_empty_digest().0;
    let preimage = node_preimage(empty, &key, &value, empty);
    let digest = blake3_hash_msg(&preimage);
    (preimage, digest)
}

fn put_state(row: &mut [Val], col: usize, state: &[u32; 16]) {
    for (i, w) in state.iter().enumerate() {
        put_limbs(row, col + 2 * i, *w);
    }
}

fn put_words8(row: &mut [Val], col: usize, words: &[u32; 8]) {
    for (i, w) in words.iter().enumerate() {
        put_limbs(row, col + 2 * i, *w);
    }
}

fn put_words64(row: &mut [Val], col: usize, words: &[u32; 64]) {
    for (i, w) in words.iter().enumerate() {
        put_limbs(row, col + 2 * i, *w);
    }
}

impl<F> BaseAir<F> for Blake3CompressAir {
    fn width(&self) -> usize {
        C_WIDTH
    }

    fn num_public_values(&self) -> usize {
        C_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut cols: Vec<usize> = (COL_S..COL_S + 32).collect();
        cols.extend(COL_SO..COL_SO + 32);
        cols.extend(COL_GI..COL_GI + 8);
        cols.extend(COL_RND..COL_RND + 7);
        cols.push(COL_KG);
        cols.push(COL_KO);
        cols.extend(COL_OI..COL_OI + 8);
        cols.push(COL_STEPR);
        cols.push(COL_LASTG);
        cols.extend(COL_MSG..COL_MSG + 32);
        cols.extend(COL_MSCH..COL_MSCH + 32);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

fn eval_compress_gadget<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
) -> (Vec<AB::Var>, Vec<AB::Var>, Vec<AB::Var>) {
    let kg = cur[COL_KG];
    let ko = cur[COL_KO];
    let stepr = cur[COL_STEPR];
    let lastg = cur[COL_LASTG];
    builder.assert_bool(kg);
    builder.assert_bool(ko);
    builder.assert_bool(stepr);
    builder.assert_bool(lastg);

    let mut gi_sum = AB::Expr::ZERO;
    let gi: Vec<AB::Var> = (0..8).map(|i| cur[COL_GI + i]).collect();
    for &g in &gi {
        builder.assert_bool(g);
        gi_sum = gi_sum + g.into();
    }
    builder.assert_eq(gi_sum, kg);

    let mut rnd_sum = AB::Expr::ZERO;
    let rnd: Vec<AB::Var> = (0..7).map(|i| cur[COL_RND + i]).collect();
    for &r in &rnd {
        builder.assert_bool(r);
        rnd_sum = rnd_sum + r.into();
    }
    builder.assert_eq(rnd_sum, kg);

    let mut oi_sum = AB::Expr::ZERO;
    let oi: Vec<AB::Var> = (0..8).map(|i| cur[COL_OI + i]).collect();
    for &o in &oi {
        builder.assert_bool(o);
        oi_sum = oi_sum + o.into();
    }
    builder.assert_eq(oi_sum, ko);

    builder.assert_eq(stepr, gi[7] * (AB::Expr::ONE - rnd[6]));
    builder.assert_eq(lastg, gi[7] * rnd[6]);

    eval_g(builder, cur);

    let mut alo = AB::Expr::ZERO;
    let mut ahi = AB::Expr::ZERO;
    let mut blo = AB::Expr::ZERO;
    let mut bhi = AB::Expr::ZERO;
    let mut clo = AB::Expr::ZERO;
    let mut chi = AB::Expr::ZERO;
    let mut dlo = AB::Expr::ZERO;
    let mut dhi = AB::Expr::ZERO;
    for k in 0..8 {
        let [ai, bi, ci, di] = G_IDX[k];
        alo = alo + gi[k] * cur[COL_S + 2 * ai];
        ahi = ahi + gi[k] * cur[COL_S + 2 * ai + 1];
        blo = blo + gi[k] * cur[COL_S + 2 * bi];
        bhi = bhi + gi[k] * cur[COL_S + 2 * bi + 1];
        clo = clo + gi[k] * cur[COL_S + 2 * ci];
        chi = chi + gi[k] * cur[COL_S + 2 * ci + 1];
        dlo = dlo + gi[k] * cur[COL_S + 2 * di];
        dhi = dhi + gi[k] * cur[COL_S + 2 * di + 1];
    }
    builder.assert_eq(cur[COL_A], alo);
    builder.assert_eq(cur[COL_A + 1], ahi);
    builder.assert_eq(cur[COL_B], blo);
    builder.assert_eq(cur[COL_B + 1], bhi);
    builder.assert_eq(cur[COL_C], clo);
    builder.assert_eq(cur[COL_C + 1], chi);
    builder.assert_eq(cur[COL_D], dlo);
    builder.assert_eq(cur[COL_D + 1], dhi);
    for j in 0..16 {
        let mut lo = AB::Expr::ZERO;
        let mut hi = AB::Expr::ZERO;
        for r in 0..7 {
            let src = MSG_SCHEDULE[r][j];
            lo = lo + rnd[r] * cur[COL_MSG + 2 * src];
            hi = hi + rnd[r] * cur[COL_MSG + 2 * src + 1];
        }
        builder.assert_eq(cur[COL_MSCH + 2 * j], lo);
        builder.assert_eq(cur[COL_MSCH + 2 * j + 1], hi);
    }
    let mut xlo = AB::Expr::ZERO;
    let mut xhi = AB::Expr::ZERO;
    let mut ylo = AB::Expr::ZERO;
    let mut yhi = AB::Expr::ZERO;
    for k in 0..8 {
        xlo = xlo + gi[k] * cur[COL_MSCH + 4 * k];
        xhi = xhi + gi[k] * cur[COL_MSCH + 4 * k + 1];
        ylo = ylo + gi[k] * cur[COL_MSCH + 4 * k + 2];
        yhi = yhi + gi[k] * cur[COL_MSCH + 4 * k + 3];
    }
    builder.assert_eq(cur[COL_X], xlo);
    builder.assert_eq(cur[COL_X + 1], xhi);
    builder.assert_eq(cur[COL_Y], ylo);
    builder.assert_eq(cur[COL_Y + 1], yhi);
    for j in 0..16 {
        let mut w = AB::Expr::ZERO;
        let mut nlo = AB::Expr::ZERO;
        let mut nhi = AB::Expr::ZERO;
        for k in 0..8 {
            let [ai, bi, ci, di] = G_IDX[k];
            if j == ai {
                w = w + gi[k].into();
                nlo = nlo + gi[k] * cur[COL_AO];
                nhi = nhi + gi[k] * cur[COL_AO + 1];
            } else if j == bi {
                w = w + gi[k].into();
                nlo = nlo + gi[k] * cur[COL_BO];
                nhi = nhi + gi[k] * cur[COL_BO + 1];
            } else if j == ci {
                w = w + gi[k].into();
                nlo = nlo + gi[k] * cur[COL_CO];
                nhi = nhi + gi[k] * cur[COL_CO + 1];
            } else if j == di {
                w = w + gi[k].into();
                nlo = nlo + gi[k] * cur[COL_DO];
                nhi = nhi + gi[k] * cur[COL_DO + 1];
            }
        }
        builder.assert_eq(
            cur[COL_SO + 2 * j],
            (AB::Expr::ONE - w.clone()) * cur[COL_S + 2 * j] + nlo,
        );
        builder.assert_eq(
            cur[COL_SO + 2 * j + 1],
            (AB::Expr::ONE - w) * cur[COL_S + 2 * j + 1] + nhi,
        );
    }

    let xl = std::array::from_fn::<_, BITS, _>(|i| cur[COL_XBITS + i]);
    let xr = std::array::from_fn::<_, BITS, _>(|i| cur[COL_XBITS + BITS + i]);
    let xx = std::array::from_fn::<_, BITS, _>(|i| cur[COL_XBITS + 2 * BITS + i]);
    for b in xl.iter().chain(xr.iter()).chain(xx.iter()) {
        builder.assert_bool(*b);
    }
    pack_limbs(builder, cur, COL_XL, &xl);
    pack_limbs(builder, cur, COL_XR, &xr);
    pack_limbs(builder, cur, COL_XX, &xx);
    for i in 0..BITS {
        builder.assert_eq(
            xx[i],
            xl[i] + xr[i] - AB::Expr::from(field(2)) * xl[i] * xr[i],
        );
    }
    let mut llo = AB::Expr::ZERO;
    let mut lhi = AB::Expr::ZERO;
    let mut rlo = AB::Expr::ZERO;
    let mut rhi = AB::Expr::ZERO;
    for i in 0..8 {
        llo = llo + oi[i] * cur[COL_S + 2 * i];
        lhi = lhi + oi[i] * cur[COL_S + 2 * i + 1];
        rlo = rlo + oi[i] * cur[COL_S + 2 * (i + 8)];
        rhi = rhi + oi[i] * cur[COL_S + 2 * (i + 8) + 1];
    }
    builder.assert_eq(cur[COL_XL], llo);
    builder.assert_eq(cur[COL_XL + 1], lhi);
    builder.assert_eq(cur[COL_XR], rlo);
    builder.assert_eq(cur[COL_XR + 1], rhi);
    (gi, rnd, oi)
}

impl<AB: AirBuilder<F = Val>> Air<AB> for Blake3CompressAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; C_PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..C_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..C_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };

        let kg = cur[COL_KG];
        let ko = cur[COL_KO];
        let stepr = cur[COL_STEPR];
        let lastg = cur[COL_LASTG];
        builder.assert_one(kg + ko);
        builder.assert_zero(kg * ko);
        let (gi, rnd, oi) = eval_compress_gadget(builder, &cur);
        for i in 0..8 {
            let mut p = builder.when(oi[i]);
            p.assert_eq(cur[COL_XX], pis[32 + 2 * i]);
            p.assert_eq(cur[COL_XX + 1], pis[32 + 2 * i + 1]);
        }

        {
            let mut first = builder.when_first_row();
            first.assert_one(kg);
            first.assert_zero(ko);
            first.assert_one(gi[0]);
            first.assert_one(rnd[0]);
            let init = init_state();
            for (j, w) in init.iter().enumerate() {
                first.assert_eq(cur[COL_S + 2 * j], AB::Expr::from(field(lo(*w) as u64)));
                first.assert_eq(cur[COL_S + 2 * j + 1], AB::Expr::from(field(hi(*w) as u64)));
            }
            for i in 0..32 {
                first.assert_eq(cur[COL_MSG + i], pis[i]);
            }
        }
        {
            let mut last = builder.when_last_row();
            last.assert_one(ko);
            last.assert_one(oi[7]);
        }
        {
            let mut t = builder.when_transition();
            for j in 0..32 {
                t.assert_eq(nxt[COL_S + j], cur[COL_SO + j]);
            }
            t.assert_eq(nxt[COL_KG], kg - lastg);
            t.assert_eq(nxt[COL_KO], lastg + ko * (AB::Expr::ONE - oi[7]));
            t.assert_eq(nxt[COL_GI], stepr);
            for k in 1..8 {
                t.assert_eq(nxt[COL_GI + k], gi[k - 1] * (AB::Expr::ONE - gi[7]));
            }
            t.assert_eq(nxt[COL_RND], rnd[0] * (AB::Expr::ONE - gi[7]));
            for r in 1..7 {
                t.assert_eq(
                    nxt[COL_RND + r],
                    rnd[r] * (AB::Expr::ONE - gi[7]) + rnd[r - 1] * stepr,
                );
            }
            for i in 0..32 {
                t.assert_eq(nxt[COL_MSG + i], cur[COL_MSG + i]);
            }
            t.assert_eq(nxt[COL_OI], lastg);
            for i in 1..8 {
                t.assert_eq(nxt[COL_OI + i], oi[i - 1] * (AB::Expr::ONE - oi[7]));
            }
        }
    }
}

fn generate_compress_trace(block: [u8; 64]) -> RowMajorMatrix<Val> {
    generate_compress_trace_ex(block, IV, 64, CHUNK_START | CHUNK_END | ROOT)
}

fn generate_compress_trace_ex(
    block: [u8; 64],
    cv_in: [u32; 8],
    block_len: u8,
    flags: u8,
) -> RowMajorMatrix<Val> {
    let msg = block_words(&block);
    let mut state = init_block_state(cv_in, block_len, flags);
    let mut values = vec![Val::ZERO; C_ROWS * C_WIDTH];
    let mut step = 0usize;
    for r in 0..7 {
        for k in 0..8 {
            let [ai, bi, ci, di] = G_IDX[k];
            let g = Blake3G {
                a: state[ai],
                b: state[bi],
                c: state[ci],
                d: state[di],
                x: msg[MSG_SCHEDULE[r][2 * k]],
                y: msg[MSG_SCHEDULE[r][2 * k + 1]],
            };
            let row = &mut values[step * C_WIDTH..(step + 1) * C_WIDTH];
            fill_g_columns(row, g);
            put_state(row, COL_S, &state);
            let [ao, bo, co, d_out] = g.apply();
            state[ai] = ao;
            state[bi] = bo;
            state[ci] = co;
            state[di] = d_out;
            put_state(row, COL_SO, &state);
            put_state(row, COL_MSG, &msg);
            for j in 0..16 {
                put_limbs(row, COL_MSCH + 2 * j, msg[MSG_SCHEDULE[r][j]]);
            }
            row[COL_GI + k] = Val::ONE;
            row[COL_RND + r] = Val::ONE;
            row[COL_KG] = Val::ONE;
            row[COL_STEPR] = if k == 7 && r + 1 < 7 {
                Val::ONE
            } else {
                Val::ZERO
            };
            row[COL_LASTG] = if k == 7 && r + 1 == 7 {
                Val::ONE
            } else {
                Val::ZERO
            };
            step += 1;
        }
    }
    debug_assert_eq!(step, N_G);
    let mut cv = cv_in;
    blake3_compress(&mut cv, &block, block_len, 0, flags);
    for i in 0..8 {
        debug_assert_eq!(state[i] ^ state[i + 8], cv[i]);
        let row = &mut values[(N_G + i) * C_WIDTH..(N_G + i + 1) * C_WIDTH];
        fill_g_columns(
            row,
            Blake3G {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                x: 0,
                y: 0,
            },
        );
        put_state(row, COL_S, &state);
        put_state(row, COL_SO, &state);
        put_state(row, COL_MSG, &msg);
        row[COL_KO] = Val::ONE;
        row[COL_OI + i] = Val::ONE;
        put_limbs(row, COL_XL, state[i]);
        put_limbs(row, COL_XR, state[i + 8]);
        put_limbs(row, COL_XX, cv[i]);
        for b in 0..BITS {
            row[COL_XBITS + b] = field(((state[i] >> b) & 1) as u64);
            row[COL_XBITS + BITS + b] = field(((state[i + 8] >> b) & 1) as u64);
            row[COL_XBITS + 2 * BITS + b] = field(((cv[i] >> b) & 1) as u64);
        }
    }
    RowMajorMatrix::new(values, C_WIDTH)
}

fn public_compress(block: [u8; 64]) -> [Val; C_PIS] {
    let msg = block_words(&block);
    let mut cv = IV;
    blake3_compress(&mut cv, &block, 64, 0, CHUNK_START | CHUNK_END | ROOT);
    let mut pis = [Val::ZERO; C_PIS];
    for i in 0..16 {
        pis[2 * i] = field(lo(msg[i]) as u64);
        pis[2 * i + 1] = field(hi(msg[i]) as u64);
    }
    for i in 0..8 {
        pis[32 + 2 * i] = field(lo(cv[i]) as u64);
        pis[32 + 2 * i + 1] = field(hi(cv[i]) as u64);
    }
    pis
}

#[derive(Clone, Debug)]
pub struct Blake3CompressProof {
    pub bytes: Vec<u8>,
}

pub fn prove_compress_with(
    block: [u8; 64],
    class: FriClass,
) -> Result<Blake3CompressProof, ProveError> {
    let config = make_config(class);
    let trace = generate_compress_trace(block);
    let pis = public_compress(block);
    let proof = prove(&config, &Blake3CompressAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(Blake3CompressProof { bytes })
}

pub fn verify_compress_with(
    block: [u8; 64],
    proof: &Blake3CompressProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_compress(block);
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &Blake3CompressAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_compress_and_report_with(
    block: [u8; 64],
    class: FriClass,
) -> Result<(Blake3CompressProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_compress_with(block, class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_compress_with(block, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

pub struct Blake3PathAir;

fn words32(bytes: &[u8; 32]) -> [u32; 8] {
    let mut w = [0u32; 8];
    for i in 0..8 {
        w[i] = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("4"));
    }
    w
}

fn assert_init_state<AB: AirBuilder<F = Val>>(b: &mut AB, cur: &[AB::Var]) {
    let init = init_state();
    for (j, w) in init.iter().enumerate() {
        b.assert_eq(cur[COL_S + 2 * j], AB::Expr::from(field(lo(*w) as u64)));
        b.assert_eq(cur[COL_S + 2 * j + 1], AB::Expr::from(field(hi(*w) as u64)));
    }
}

impl<F> BaseAir<F> for Blake3PathAir {
    fn width(&self) -> usize {
        P_WIDTH
    }

    fn num_public_values(&self) -> usize {
        P_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut cols: Vec<usize> = (COL_S..COL_S + 32).collect();
        cols.extend(COL_SO..COL_SO + 32);
        cols.extend(COL_GI..COL_GI + 8);
        cols.extend(COL_RND..COL_RND + 7);
        cols.push(COL_KG);
        cols.push(COL_KO);
        cols.extend(COL_OI..COL_OI + 8);
        cols.push(COL_STEPR);
        cols.push(COL_LASTG);
        cols.extend(COL_MSG..COL_MSG + 32);
        cols.extend(COL_H..COL_H + BLAKE3_PATH_LEN);
        cols.push(COL_PAD);
        cols.extend(COL_SIB..COL_SIB + 16);
        cols.extend(COL_DIG..COL_DIG + 16);
        cols.push(COL_ENDH);
        cols.push(COL_WRAPH);
        cols.push(COL_ROOTCHK);
        cols.extend(COL_DIGO..COL_DIGO + 16);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for Blake3PathAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; P_PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..P_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..P_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };

        let kg = cur[COL_KG];
        let ko = cur[COL_KO];
        let pad = cur[COL_PAD];
        let stepr = cur[COL_STEPR];
        let lastg = cur[COL_LASTG];
        let endh = cur[COL_ENDH];
        let wraph = cur[COL_WRAPH];
        let rootchk = cur[COL_ROOTCHK];
        builder.assert_bool(pad);
        builder.assert_bool(endh);
        builder.assert_bool(wraph);
        builder.assert_bool(rootchk);
        builder.assert_one(kg + ko + pad);
        builder.assert_zero(kg * ko);
        builder.assert_zero(kg * pad);
        builder.assert_zero(ko * pad);

        let (gi, rnd, oi) = eval_compress_gadget(builder, &cur);

        let mut h_sum = pad.into();
        let h: Vec<AB::Var> = (0..BLAKE3_PATH_LEN).map(|i| cur[COL_H + i]).collect();
        for &hi in &h {
            builder.assert_bool(hi);
            h_sum = h_sum + hi.into();
        }
        builder.assert_one(h_sum);

        builder.assert_eq(endh, ko * oi[7]);
        builder.assert_eq(wraph, endh * (AB::Expr::ONE - h[BLAKE3_PATH_LEN - 1]));
        builder.assert_eq(rootchk, endh * h[BLAKE3_PATH_LEN - 1]);
        for i in 0..8 {
            builder.assert_eq(
                cur[COL_DIGO + 2 * i],
                oi[i] * cur[COL_XX] + (AB::Expr::ONE - oi[i]) * cur[COL_DIG + 2 * i],
            );
            builder.assert_eq(
                cur[COL_DIGO + 2 * i + 1],
                oi[i] * cur[COL_XX + 1] + (AB::Expr::ONE - oi[i]) * cur[COL_DIG + 2 * i + 1],
            );
        }

        {
            let mut first = builder.when_first_row();
            first.assert_one(kg);
            first.assert_zero(ko);
            first.assert_zero(pad);
            first.assert_one(gi[0]);
            first.assert_one(rnd[0]);
            first.assert_one(h[0]);
            assert_init_state(&mut first, &cur);
            for i in 0..16 {
                first.assert_eq(cur[COL_MSG + i], pis[i]);
                first.assert_eq(cur[COL_MSG + 16 + i], cur[COL_SIB + i]);
                first.assert_zero(cur[COL_DIG + i]);
            }
        }
        {
            let mut last = builder.when_last_row();
            last.assert_one(pad);
            for i in 0..16 {
                last.assert_eq(cur[COL_DIG + i], pis[16 + i]);
            }
        }
        {
            let mut t = builder.when_transition();
            t.assert_eq(nxt[COL_PAD], pad + rootchk);
            t.assert_eq(nxt[COL_KG], kg - lastg + wraph);
            t.assert_eq(nxt[COL_KO], lastg + ko * (AB::Expr::ONE - oi[7]));
            t.assert_eq(nxt[COL_GI], stepr + wraph);
            for k in 1..8 {
                t.assert_eq(nxt[COL_GI + k], gi[k - 1] * (AB::Expr::ONE - gi[7]));
            }
            t.assert_eq(nxt[COL_RND], rnd[0] * (AB::Expr::ONE - gi[7]) + wraph);
            for r in 1..7 {
                t.assert_eq(
                    nxt[COL_RND + r],
                    rnd[r] * (AB::Expr::ONE - gi[7]) + rnd[r - 1] * stepr,
                );
            }
            t.assert_eq(nxt[COL_OI], lastg);
            for i in 1..8 {
                t.assert_eq(nxt[COL_OI + i], oi[i - 1] * (AB::Expr::ONE - oi[7]));
            }
            t.assert_eq(nxt[COL_H], h[0] * (AB::Expr::ONE - endh));
            for k in 1..BLAKE3_PATH_LEN {
                t.assert_eq(
                    nxt[COL_H + k],
                    h[k] * (AB::Expr::ONE - endh) + h[k - 1] * wraph,
                );
            }
            let init = init_state();
            for j in 0..16 {
                let init_lo = AB::Expr::from(field(lo(init[j]) as u64));
                let init_hi = AB::Expr::from(field(hi(init[j]) as u64));
                t.assert_eq(
                    nxt[COL_S + 2 * j],
                    wraph * init_lo
                        + pad * cur[COL_S + 2 * j]
                        + (AB::Expr::ONE - wraph - pad) * cur[COL_SO + 2 * j],
                );
                t.assert_eq(
                    nxt[COL_S + 2 * j + 1],
                    wraph * init_hi
                        + pad * cur[COL_S + 2 * j + 1]
                        + (AB::Expr::ONE - wraph - pad) * cur[COL_SO + 2 * j + 1],
                );
            }
            for i in 0..16 {
                t.assert_eq(nxt[COL_DIG + i], cur[COL_DIGO + i]);
                t.assert_eq(
                    nxt[COL_MSG + i],
                    wraph * cur[COL_DIGO + i] + (AB::Expr::ONE - wraph) * cur[COL_MSG + i],
                );
            }
            for i in 0..16 {
                t.assert_eq(
                    nxt[COL_MSG + 16 + i],
                    wraph * nxt[COL_SIB + i] + (AB::Expr::ONE - wraph) * cur[COL_MSG + 16 + i],
                );
                t.assert_zero((AB::Expr::ONE - wraph) * (nxt[COL_SIB + i] - cur[COL_SIB + i]));
            }
        }
        {
            let mut r = builder.when(rootchk);
            for i in 0..7 {
                r.assert_eq(cur[COL_DIG + 2 * i], pis[16 + 2 * i]);
                r.assert_eq(cur[COL_DIG + 2 * i + 1], pis[16 + 2 * i + 1]);
            }
            r.assert_eq(cur[COL_XX], pis[16 + 14]);
            r.assert_eq(cur[COL_XX + 1], pis[16 + 15]);
        }
    }
}

fn generate_path_trace(leaf: [u8; 32], siblings: &[[u8; 32]]) -> RowMajorMatrix<Val> {
    assert_eq!(siblings.len(), BLAKE3_PATH_LEN);
    let mut values = vec![Val::ZERO; P_ROWS * P_WIDTH];
    let mut digest = leaf;
    let mut dig_words = [0u32; 8];
    for h in 0..BLAKE3_PATH_LEN {
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(&digest);
        block[32..].copy_from_slice(&siblings[h]);
        let base = h * C_ROWS;
        write_compress_prefix(&mut values, base, P_WIDTH, block);
        let cv = words32(&blake3_hash64(block));
        let sib_w = words32(&siblings[h]);
        for r in 0..C_ROWS {
            let row = &mut values[(base + r) * P_WIDTH..(base + r + 1) * P_WIDTH];
            row[COL_H + h] = Val::ONE;
            put_words8(row, COL_SIB, &sib_w);
            put_words8(row, COL_DIG, &dig_words);
            let mut digo = dig_words;
            if r >= N_G {
                digo[r - N_G] = cv[r - N_G];
                dig_words[r - N_G] = cv[r - N_G];
            }
            put_words8(row, COL_DIGO, &digo);
            if r + 1 == C_ROWS {
                row[COL_ENDH] = Val::ONE;
                if h + 1 < BLAKE3_PATH_LEN {
                    row[COL_WRAPH] = Val::ONE;
                } else {
                    row[COL_ROOTCHK] = Val::ONE;
                }
            }
        }
        digest = blake3_hash64(block);
        debug_assert_eq!(dig_words, cv);
    }
    let last_dig = dig_words;
    let last = values[(P_ACTIVE - 1) * P_WIDTH..P_ACTIVE * P_WIDTH].to_vec();
    for i in P_ACTIVE..P_ROWS {
        let row = &mut values[i * P_WIDTH..(i + 1) * P_WIDTH];
        fill_g_columns(
            row,
            Blake3G {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                x: 0,
                y: 0,
            },
        );
        row[COL_S..COL_S + 32].copy_from_slice(&last[COL_S..COL_S + 32]);
        row[COL_SO..COL_SO + 32].copy_from_slice(&last[COL_SO..COL_SO + 32]);
        row[COL_MSG..COL_MSG + 32].copy_from_slice(&last[COL_MSG..COL_MSG + 32]);
        row[COL_SIB..COL_SIB + 16].copy_from_slice(&last[COL_SIB..COL_SIB + 16]);
        row[COL_PAD] = Val::ONE;
        put_words8(row, COL_DIG, &last_dig);
        put_words8(row, COL_DIGO, &last_dig);
    }
    RowMajorMatrix::new(values, P_WIDTH)
}

fn write_compress_prefix(values: &mut [Val], base: usize, stride: usize, block: [u8; 64]) {
    let single = generate_compress_trace(block);
    for r in 0..C_ROWS {
        let src = &single.values[r * C_WIDTH..(r + 1) * C_WIDTH];
        let dst = &mut values[(base + r) * stride..(base + r) * stride + C_WIDTH];
        dst.copy_from_slice(src);
    }
}

fn public_path(leaf: [u8; 32], siblings: &[[u8; 32]]) -> [Val; P_PIS] {
    let root = blake3_path(leaf, siblings);
    let mut pis = [Val::ZERO; P_PIS];
    let lw = words32(&leaf);
    let rw = words32(&root);
    for i in 0..8 {
        pis[2 * i] = field(lo(lw[i]) as u64);
        pis[2 * i + 1] = field(hi(lw[i]) as u64);
        pis[16 + 2 * i] = field(lo(rw[i]) as u64);
        pis[16 + 2 * i + 1] = field(hi(rw[i]) as u64);
    }
    pis
}

#[derive(Clone, Debug)]
pub struct Blake3PathProof {
    pub bytes: Vec<u8>,
}

pub fn prove_blake3_path_with(
    leaf: [u8; 32],
    siblings: Vec<[u8; 32]>,
    class: FriClass,
) -> Result<Blake3PathProof, ProveError> {
    let config = make_config(class);
    let trace = generate_path_trace(leaf, &siblings);
    let pis = public_path(leaf, &siblings);
    let proof = prove(&config, &Blake3PathAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(Blake3PathProof { bytes })
}

pub fn verify_blake3_path_with(
    leaf: [u8; 32],
    siblings: Vec<[u8; 32]>,
    proof: &Blake3PathProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_path(leaf, &siblings);
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &Blake3PathAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_blake3_path_and_report_with(
    leaf: [u8; 32],
    siblings: Vec<[u8; 32]>,
    class: FriClass,
) -> Result<(Blake3PathProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_blake3_path_with(leaf, siblings.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_blake3_path_with(leaf, siblings, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

/// Resting-map `node_digest`: 4 CV-chained compressions. Not a path of 20.
pub struct NodeDigestAir;

fn padded_msg_words_n(msg: &[u8]) -> [u32; 64] {
    assert!(!msg.is_empty() && msg.len() <= 256);
    let w = padded_msg_words_80(msg);
    let mut out = [0u32; 64];
    out.copy_from_slice(&w[..64]);
    out
}

fn padded_msg_words_80(msg: &[u8]) -> [u32; 80] {
    assert!(!msg.is_empty() && msg.len() <= 320);
    let mut bytes = [0u8; 320];
    bytes[..msg.len()].copy_from_slice(msg);
    let mut words = [0u32; 80];
    for i in 0..80 {
        words[i] = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("4"));
    }
    words
}

fn padded_msg_words(msg: &[u8]) -> [u32; 64] {
    assert_eq!(msg.len(), RESTING_NODE_BYTES);
    padded_msg_words_n(msg)
}

fn opening_nblocks(msg_len: usize) -> usize {
    msg_len.div_ceil(64)
}

fn opening_last_blen(msg_len: usize) -> u8 {
    let rem = (msg_len % 64) as u8;
    if rem == 0 {
        64
    } else {
        rem
    }
}

fn opening_block_len_flags(i: usize, nblocks: usize, msg_len: usize) -> (u8, u8) {
    let last = i + 1 == nblocks;
    let blen = if last { opening_last_blen(msg_len) } else { 64 };
    let mut flags = 0u8;
    if i == 0 {
        flags |= CHUNK_START;
    }
    if last {
        flags |= CHUNK_END | ROOT;
    }
    (blen, flags)
}

fn block_from_words(words: &[u32], i: usize) -> [u8; 64] {
    let mut block = [0u8; 64];
    for j in 0..16 {
        block[j * 4..j * 4 + 4].copy_from_slice(&words[i * 16 + j].to_le_bytes());
    }
    block
}

impl<F> BaseAir<F> for NodeDigestAir {
    fn width(&self) -> usize {
        N_WIDTH
    }

    fn num_public_values(&self) -> usize {
        N_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut cols: Vec<usize> = (COL_S..COL_S + 32).collect();
        cols.extend(COL_SO..COL_SO + 32);
        cols.extend(COL_GI..COL_GI + 8);
        cols.extend(COL_RND..COL_RND + 7);
        cols.push(COL_KG);
        cols.push(COL_KO);
        cols.extend(COL_OI..COL_OI + 8);
        cols.push(COL_STEPR);
        cols.push(COL_LASTG);
        cols.extend(COL_MSG..COL_MSG + 32);
        cols.extend(COL_NB..COL_NB + NODE_DIGEST_BLOCKS);
        cols.push(COL_ENDN);
        cols.push(COL_WRAPN);
        cols.push(COL_ROOTN);
        cols.extend(COL_NCV..COL_NCV + 16);
        cols.extend(COL_NCVO..COL_NCVO + 16);
        cols.extend(COL_NMSG..COL_NMSG + 32);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for NodeDigestAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; N_PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..N_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..N_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };

        let kg = cur[COL_KG];
        let ko = cur[COL_KO];
        let stepr = cur[COL_STEPR];
        let lastg = cur[COL_LASTG];
        let endn = cur[COL_ENDN];
        let wrapn = cur[COL_WRAPN];
        let rootn = cur[COL_ROOTN];
        builder.assert_bool(endn);
        builder.assert_bool(wrapn);
        builder.assert_bool(rootn);
        builder.assert_one(kg + ko);
        builder.assert_zero(kg * ko);

        let (gi, rnd, oi) = eval_compress_gadget(builder, &cur);

        let mut b_sum = AB::Expr::ZERO;
        let b: Vec<AB::Var> = (0..NODE_DIGEST_BLOCKS).map(|i| cur[COL_NB + i]).collect();
        for &bi in &b {
            builder.assert_bool(bi);
            b_sum = b_sum + bi.into();
        }
        builder.assert_one(b_sum);

        builder.assert_eq(endn, ko * oi[7]);
        builder.assert_eq(wrapn, endn * (AB::Expr::ONE - b[3]));
        builder.assert_eq(rootn, endn * b[3]);
        for i in 0..8 {
            builder.assert_eq(
                cur[COL_NCVO + 2 * i],
                oi[i] * cur[COL_XX] + (AB::Expr::ONE - oi[i]) * cur[COL_NCV + 2 * i],
            );
            builder.assert_eq(
                cur[COL_NCVO + 2 * i + 1],
                oi[i] * cur[COL_XX + 1] + (AB::Expr::ONE - oi[i]) * cur[COL_NCV + 2 * i + 1],
            );
        }

        for k in 0..NODE_DIGEST_BLOCKS {
            let mut bk = builder.when(b[k]);
            for j in 0..32 {
                bk.assert_eq(cur[COL_MSG + j], pis[32 * k + j]);
            }
        }
        for k in 0..NODE_DIGEST_BLOCKS - 1 {
            let mut bk = builder.when(b[k]);
            for j in 0..32 {
                bk.assert_eq(cur[COL_NMSG + j], pis[32 * (k + 1) + j]);
            }
        }
        {
            let mut lastb = builder.when(b[3]);
            for j in 0..32 {
                lastb.assert_zero(cur[COL_NMSG + j]);
            }
        }

        {
            let mut first = builder.when_first_row();
            first.assert_one(kg);
            first.assert_zero(ko);
            first.assert_one(gi[0]);
            first.assert_one(rnd[0]);
            first.assert_one(b[0]);
            let init = init_block_state(IV, 64, CHUNK_START);
            for (j, w) in init.iter().enumerate() {
                first.assert_eq(cur[COL_S + 2 * j], AB::Expr::from(field(lo(*w) as u64)));
                first.assert_eq(cur[COL_S + 2 * j + 1], AB::Expr::from(field(hi(*w) as u64)));
            }
            for i in 0..8 {
                first.assert_eq(
                    cur[COL_NCV + 2 * i],
                    AB::Expr::from(field(lo(IV[i]) as u64)),
                );
                first.assert_eq(
                    cur[COL_NCV + 2 * i + 1],
                    AB::Expr::from(field(hi(IV[i]) as u64)),
                );
            }
        }
        {
            let mut last = builder.when_last_row();
            last.assert_one(ko);
            last.assert_one(oi[7]);
            last.assert_one(b[3]);
            last.assert_one(rootn);
        }
        {
            let mut t = builder.when_transition();
            t.assert_eq(nxt[COL_KG], kg - lastg + wrapn);
            t.assert_eq(nxt[COL_KO], lastg + ko * (AB::Expr::ONE - oi[7]));
            t.assert_eq(nxt[COL_GI], stepr + wrapn);
            for k in 1..8 {
                t.assert_eq(nxt[COL_GI + k], gi[k - 1] * (AB::Expr::ONE - gi[7]));
            }
            t.assert_eq(nxt[COL_RND], rnd[0] * (AB::Expr::ONE - gi[7]) + wrapn);
            for r in 1..7 {
                t.assert_eq(
                    nxt[COL_RND + r],
                    rnd[r] * (AB::Expr::ONE - gi[7]) + rnd[r - 1] * stepr,
                );
            }
            t.assert_eq(nxt[COL_OI], lastg);
            for i in 1..8 {
                t.assert_eq(nxt[COL_OI + i], oi[i - 1] * (AB::Expr::ONE - oi[7]));
            }
            t.assert_eq(nxt[COL_NB], b[0] * (AB::Expr::ONE - endn));
            for k in 1..NODE_DIGEST_BLOCKS {
                t.assert_eq(
                    nxt[COL_NB + k],
                    b[k] * (AB::Expr::ONE - endn) + b[k - 1] * wrapn,
                );
            }
            let iv4 = [IV[0], IV[1], IV[2], IV[3]];
            let next_len = AB::Expr::from(field(64)) - AB::Expr::from(field(40)) * nxt[COL_NB + 3];
            let next_flg = AB::Expr::from(field((CHUNK_END | ROOT) as u64)) * nxt[COL_NB + 3];
            for j in 0..8 {
                t.assert_eq(
                    nxt[COL_S + 2 * j],
                    wrapn * cur[COL_NCVO + 2 * j] + (AB::Expr::ONE - wrapn) * cur[COL_SO + 2 * j],
                );
                t.assert_eq(
                    nxt[COL_S + 2 * j + 1],
                    wrapn * cur[COL_NCVO + 2 * j + 1]
                        + (AB::Expr::ONE - wrapn) * cur[COL_SO + 2 * j + 1],
                );
            }
            for j in 0..4 {
                let iv_lo = AB::Expr::from(field(lo(iv4[j]) as u64));
                let iv_hi = AB::Expr::from(field(hi(iv4[j]) as u64));
                t.assert_eq(
                    nxt[COL_S + 16 + 2 * j],
                    wrapn * iv_lo + (AB::Expr::ONE - wrapn) * cur[COL_SO + 16 + 2 * j],
                );
                t.assert_eq(
                    nxt[COL_S + 17 + 2 * j],
                    wrapn * iv_hi + (AB::Expr::ONE - wrapn) * cur[COL_SO + 17 + 2 * j],
                );
            }
            for j in 24..28 {
                t.assert_eq(nxt[COL_S + j], (AB::Expr::ONE - wrapn) * cur[COL_SO + j]);
            }
            t.assert_eq(
                nxt[COL_S + 28],
                wrapn * next_len + (AB::Expr::ONE - wrapn) * cur[COL_SO + 28],
            );
            t.assert_eq(nxt[COL_S + 29], (AB::Expr::ONE - wrapn) * cur[COL_SO + 29]);
            t.assert_eq(
                nxt[COL_S + 30],
                wrapn * next_flg + (AB::Expr::ONE - wrapn) * cur[COL_SO + 30],
            );
            t.assert_eq(nxt[COL_S + 31], (AB::Expr::ONE - wrapn) * cur[COL_SO + 31]);
            for i in 0..16 {
                t.assert_eq(nxt[COL_NCV + i], cur[COL_NCVO + i]);
            }
            for i in 0..32 {
                t.assert_eq(
                    nxt[COL_MSG + i],
                    wrapn * cur[COL_NMSG + i] + (AB::Expr::ONE - wrapn) * cur[COL_MSG + i],
                );
                t.assert_zero((AB::Expr::ONE - wrapn) * (nxt[COL_NMSG + i] - cur[COL_NMSG + i]));
            }
        }
        {
            let mut r = builder.when(rootn);
            for i in 0..7 {
                r.assert_eq(cur[COL_NCV + 2 * i], pis[128 + 2 * i]);
                r.assert_eq(cur[COL_NCV + 2 * i + 1], pis[128 + 2 * i + 1]);
            }
            r.assert_eq(cur[COL_XX], pis[128 + 14]);
            r.assert_eq(cur[COL_XX + 1], pis[128 + 15]);
        }
    }
}

fn write_compress_prefix_ex(
    values: &mut [Val],
    base: usize,
    stride: usize,
    block: [u8; 64],
    cv: [u32; 8],
    block_len: u8,
    flags: u8,
) {
    let single = generate_compress_trace_ex(block, cv, block_len, flags);
    for r in 0..C_ROWS {
        let src = &single.values[r * C_WIDTH..(r + 1) * C_WIDTH];
        let dst = &mut values[(base + r) * stride..(base + r) * stride + C_WIDTH];
        dst.copy_from_slice(src);
    }
}

fn fill_opening_n_cols(
    values: &mut [Val],
    stride: usize,
    row_base: usize,
    preimage: &[u8],
) -> [u32; 8] {
    let nblocks = opening_nblocks(preimage.len());
    assert!(nblocks <= 5);
    assert!(nblocks <= NODE_DIGEST_BLOCKS || stride > COL_NB4);
    let words = padded_msg_words_80(preimage);
    let mut cv = IV;
    for h in 0..nblocks {
        let (blen, flags) = opening_block_len_flags(h, nblocks, preimage.len());
        let block = block_from_words(&words, h);
        let base = row_base + h * C_ROWS;
        write_compress_prefix_ex(values, base, stride, block, cv, blen, flags);
        let mut out = cv;
        blake3_compress(&mut out, &block, blen, 0, flags);
        let next_words = if h + 1 < nblocks {
            let mut n = [0u32; 16];
            n.copy_from_slice(&words[(h + 1) * 16..(h + 2) * 16]);
            n
        } else {
            [0u32; 16]
        };
        let mut cv_words = cv;
        for r in 0..C_ROWS {
            let row = &mut values[(base + r) * stride..(base + r + 1) * stride];
            if h < NODE_DIGEST_BLOCKS {
                row[COL_NB + h] = Val::ONE;
            } else {
                row[COL_NB4] = Val::ONE;
            }
            put_words8(row, COL_NCV, &cv_words);
            let mut cvo = cv_words;
            if r >= N_G {
                cvo[r - N_G] = out[r - N_G];
                cv_words[r - N_G] = out[r - N_G];
            }
            put_words8(row, COL_NCVO, &cvo);
            put_state(row, COL_NMSG, &next_words);
            if r + 1 == C_ROWS {
                row[COL_ENDN] = Val::ONE;
                if h + 1 < nblocks {
                    row[COL_WRAPN] = Val::ONE;
                } else {
                    row[COL_ROOTN] = Val::ONE;
                }
            }
        }
        cv = out;
    }
    cv
}

fn generate_node_digest_trace(preimage: &[u8]) -> RowMajorMatrix<Val> {
    assert_eq!(preimage.len(), RESTING_NODE_BYTES);
    let mut values = vec![Val::ZERO; N_ROWS * N_WIDTH];
    fill_opening_n_cols(&mut values, N_WIDTH, 0, preimage);
    RowMajorMatrix::new(values, N_WIDTH)
}

fn public_node_digest(preimage: &[u8]) -> [Val; N_PIS] {
    let words = padded_msg_words(preimage);
    let digest = blake3_hash_msg(preimage);
    let dw = words32(&digest);
    let mut pis = [Val::ZERO; N_PIS];
    for i in 0..64 {
        pis[2 * i] = field(lo(words[i]) as u64);
        pis[2 * i + 1] = field(hi(words[i]) as u64);
    }
    for i in 0..8 {
        pis[128 + 2 * i] = field(lo(dw[i]) as u64);
        pis[128 + 2 * i + 1] = field(hi(dw[i]) as u64);
    }
    pis
}

#[derive(Clone, Debug)]
pub struct NodeDigestProof {
    pub bytes: Vec<u8>,
}

pub fn prove_node_digest_with(
    preimage: Vec<u8>,
    class: FriClass,
) -> Result<NodeDigestProof, ProveError> {
    let config = make_config(class);
    let trace = generate_node_digest_trace(&preimage);
    let pis = public_node_digest(&preimage);
    let proof = prove(&config, &NodeDigestAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(NodeDigestProof { bytes })
}

pub fn verify_node_digest_with(
    preimage: Vec<u8>,
    proof: &NodeDigestProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_node_digest(&preimage);
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &NodeDigestAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_node_digest_and_report_with(
    preimage: Vec<u8>,
    class: FriClass,
) -> Result<(NodeDigestProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_node_digest_with(preimage.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_node_digest_with(preimage, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

/// 19 chronological openings from one 8k resting upsert: 18 `node_digest` +
/// 1 OrderId prio interleaved via `start_c_prime_trace`. Same count as
/// HeightMatch; different tape (no I/INC/settlement/match). Not `F`.
pub struct NodePathAir;

impl<F> BaseAir<F> for NodePathAir {
    fn width(&self) -> usize {
        H_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NP_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        mixed_openings_one_block_next_cols()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for NodePathAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; NP_PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..H_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..H_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };
        eval_engine_tape(builder, &cur, &nxt, &pis, NODE_PATH_LEN, true);
    }
}

fn generate_node_path_trace(preimages: &[Vec<u8>]) -> RowMajorMatrix<Val> {
    generate_mixed_openings_trace(preimages, NODE_PATH_LEN, NP_ROWS, true)
}

fn public_node_path(preimages: &[Vec<u8>]) -> [Val; NP_PIS] {
    let last = blake3_hash_msg(preimages.last().expect("openings"));
    let dw = words32(&last);
    let mut pis = [Val::ZERO; NP_PIS];
    for i in 0..8 {
        pis[2 * i] = field(lo(dw[i]) as u64);
        pis[2 * i + 1] = field(hi(dw[i]) as u64);
    }
    pis
}

#[derive(Clone, Debug)]
pub struct NodePathProof {
    pub bytes: Vec<u8>,
}

pub fn prove_node_path_with(
    preimages: Vec<Vec<u8>>,
    class: FriClass,
) -> Result<NodePathProof, ProveError> {
    let config = make_config(class);
    let trace = generate_node_path_trace(&preimages);
    let pis = public_node_path(&preimages);
    let proof = prove(&config, &NodePathAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(NodePathProof { bytes })
}

pub fn verify_node_path_with(
    preimages: Vec<Vec<u8>>,
    proof: &NodePathProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_node_path(&preimages);
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &NodePathAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_node_path_and_report_with(
    preimages: Vec<Vec<u8>>,
    class: FriClass,
) -> Result<(NodePathProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_node_path_with(preimages.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_node_path_with(preimages, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

const BN_WIDTH: usize = H_WIDTH + BOOK_WIDTH;
const BN_PIS: usize = NP_PIS + BOOK_PIS;

/// Book-step stacked on 19 chronological upsert openings (18 resting + 1 prio).
/// Not engine insert, not the tape.
pub struct BookNodePathAir;

impl<F> BaseAir<F> for BookNodePathAir {
    fn width(&self) -> usize {
        BN_WIDTH
    }

    fn num_public_values(&self) -> usize {
        BN_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        mixed_openings_one_block_next_cols()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for BookNodePathAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: Vec<AB::PublicVar> = (0..BN_PIS).map(|i| pv[i]).collect();
            let cur: Vec<AB::Var> = (0..BN_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..BN_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };
        eval_engine_tape(builder, &cur[..H_WIDTH], &nxt[..H_WIDTH], &pis[..NP_PIS], NODE_PATH_LEN, true);
        eval_book(builder, &cur[H_WIDTH..], &pis[NP_PIS..]);
    }
}

fn generate_book_node_path_trace(
    preimages: &[Vec<u8>],
    stmt: &tiny_f::BookStepStatement,
) -> Result<RowMajorMatrix<Val>, ProveError> {
    let np = generate_node_path_trace(preimages);
    let book = generate_book_row(stmt)?;
    let mut values = vec![Val::ZERO; NP_ROWS * BN_WIDTH];
    for r in 0..NP_ROWS {
        let src = &np.values[r * H_WIDTH..(r + 1) * H_WIDTH];
        let dst = &mut values[r * BN_WIDTH..(r + 1) * BN_WIDTH];
        dst[..H_WIDTH].copy_from_slice(src);
        dst[H_WIDTH..].copy_from_slice(&book);
    }
    Ok(RowMajorMatrix::new(values, BN_WIDTH))
}

fn public_book_node_path(
    preimages: &[Vec<u8>],
    stmt: &tiny_f::BookStepStatement,
) -> Result<[Val; BN_PIS], ProveError> {
    let np = public_node_path(preimages);
    let book = book_public_values(stmt)?;
    let mut pis = [Val::ZERO; BN_PIS];
    pis[..NP_PIS].copy_from_slice(&np);
    pis[NP_PIS..].copy_from_slice(&book);
    Ok(pis)
}

#[derive(Clone, Debug)]
pub struct BookNodePathProof {
    pub bytes: Vec<u8>,
}

pub fn prove_book_node_path_with(
    preimages: Vec<Vec<u8>>,
    stmt: tiny_f::BookStepStatement,
    class: FriClass,
) -> Result<BookNodePathProof, ProveError> {
    let config = make_config(class);
    let trace = generate_book_node_path_trace(&preimages, &stmt)?;
    let pis = public_book_node_path(&preimages, &stmt)?;
    let proof = prove(&config, &BookNodePathAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(BookNodePathProof { bytes })
}

pub fn verify_book_node_path_with(
    preimages: Vec<Vec<u8>>,
    stmt: tiny_f::BookStepStatement,
    proof: &BookNodePathProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_book_node_path(&preimages, &stmt).map_err(|_| Plonky3VerifyError::Rejected)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &BookNodePathAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_book_node_path_and_report_with(
    preimages: Vec<Vec<u8>>,
    stmt: tiny_f::BookStepStatement,
    class: FriClass,
) -> Result<(BookNodePathProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_book_node_path_with(preimages.clone(), stmt.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_book_node_path_with(preimages, stmt, &proof, class)
        .map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

/// Engine Place at 8k: 72 chronological `C'` openings (69 node + 3 prio
/// interleaved via `start_c_prime_trace`). Not 18 resting, not HeightMatch,
/// not `F`, not the 8k-book tape.
pub struct EngineInsertAir;

impl<F> BaseAir<F> for EngineInsertAir {
    fn width(&self) -> usize {
        EI_WIDTH
    }

    fn num_public_values(&self) -> usize {
        EI_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut cols: Vec<usize> = (COL_S..COL_S + 32).collect();
        cols.extend(COL_SO..COL_SO + 32);
        cols.extend(COL_GI..COL_GI + 8);
        cols.extend(COL_RND..COL_RND + 7);
        cols.push(COL_KG);
        cols.push(COL_KO);
        cols.extend(COL_OI..COL_OI + 8);
        cols.push(COL_STEPR);
        cols.push(COL_LASTG);
        cols.extend(COL_MSG..COL_MSG + 32);
        cols.extend(COL_NB..COL_NB + NODE_DIGEST_BLOCKS);
        cols.push(COL_ENDN);
        cols.push(COL_WRAPN);
        cols.push(COL_ROOTN);
        cols.extend(COL_NCV..COL_NCV + 16);
        cols.extend(COL_NCVO..COL_NCVO + 16);
        cols.extend(COL_NMSG..COL_NMSG + 32);
        cols.push(COL_BLAST);
        cols.push(COL_BLEN);
        cols.push(COL_BFLG);
        cols.extend(COL_EH..COL_EH + ENGINE_INSERT_OPENINGS);
        cols.push(COL_EPAD);
        cols.push(COL_EWRAP);
        cols.push(COL_EROOT);
        cols.extend(COL_EPRE..COL_EPRE + 128);
        cols.push(COL_EQ33);
        cols.push(COL_EQ49);
        cols.push(COL_EI_LOAD_OID);
        cols.push(COL_EI_LAT_OID0);
        cols.push(COL_EI_LAT_OID1);
        cols.push(COL_EI_LOAD_OWN);
        cols.push(COL_EI_LAT_OWN0);
        cols.push(COL_EI_CHK_OID2);
        cols.push(COL_EI_LOAD_N2);
        for i in 0..16 {
            cols.push(COL_EI_LAT_N2 + i);
        }
        cols.push(COL_EI_LOAD_S6);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S6 + i);
        }
        cols.push(COL_EI_LOAD_R40);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R40 + i);
        }
        cols.push(COL_EI_LOAD_S8);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S8 + i);
        }
        cols.push(COL_EI_LOAD_R42);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R42 + i);
        }
        cols.push(COL_EI_LOAD_S10);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S10 + i);
        }
        cols.push(COL_EI_LOAD_R44);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R44 + i);
        }
        cols.push(COL_EI_LOAD_S12);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S12 + i);
        }
        cols.push(COL_EI_LOAD_R46);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R46 + i);
        }
        cols.push(COL_EI_LOAD_S14);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S14 + i);
        }
        cols.push(COL_EI_LOAD_R48);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R48 + i);
        }
        cols.push(COL_EI_LOAD_S16);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S16 + i);
        }
        cols.push(COL_EI_LOAD_R50);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R50 + i);
        }
        cols.push(COL_EI_LOAD_S18);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S18 + i);
        }
        cols.push(COL_EI_LOAD_R52);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R52 + i);
        }
        cols.push(COL_EI_LOAD_S20);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S20 + i);
        }
        cols.push(COL_EI_LOAD_R54);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R54 + i);
        }
        cols.push(COL_EI_LOAD_S22);
        for i in 0..16 {
            cols.push(COL_EI_LAT_S22 + i);
        }
        cols.push(COL_EI_LOAD_R56);
        for i in 0..16 {
            cols.push(COL_EI_LAT_R56 + i);
        }
        for (load, lat) in [
            (COL_EI_LOAD_S24, COL_EI_LAT_S24),
            (COL_EI_LOAD_R58, COL_EI_LAT_R58),
            (COL_EI_LOAD_S26, COL_EI_LAT_S26),
            (COL_EI_LOAD_R60, COL_EI_LAT_R60),
        ] {
            cols.push(load);
            for i in 0..16 {
                cols.push(lat + i);
            }
        }
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Insert key loads: q33/q49 × hidx × rootn.
        Some(3)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for EngineInsertAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; EI_PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..EI_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..EI_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };
        eval_engine_insert(builder, &cur, &nxt, &pis);
    }
}

fn eval_engine_insert<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
    pis: &[AB::PublicVar],
) {
    let kg = cur[COL_KG];
    let ko = cur[COL_KO];
    let pad = cur[COL_EPAD];
    let stepr = cur[COL_STEPR];
    let lastg = cur[COL_LASTG];
    let endn = cur[COL_ENDN];
    let wrapn = cur[COL_WRAPN];
    let rootn = cur[COL_ROOTN];
    let blast = cur[COL_BLAST];
    let wraph = cur[COL_EWRAP];
    let nroot = cur[COL_EROOT];
    builder.assert_bool(pad);
    builder.assert_bool(endn);
    builder.assert_bool(wrapn);
    builder.assert_bool(rootn);
    builder.assert_bool(blast);
    builder.assert_bool(wraph);
    builder.assert_bool(nroot);
    builder.assert_one(kg + ko + pad);
    builder.assert_zero(kg * ko);
    builder.assert_zero(kg * pad);
    builder.assert_zero(ko * pad);

    let (gi, rnd, oi) = eval_compress_gadget(builder, &cur);

    let mut b_sum = pad.into();
    let b: Vec<AB::Var> = (0..NODE_DIGEST_BLOCKS).map(|i| cur[COL_NB + i]).collect();
    for &bi in &b {
        builder.assert_bool(bi);
        b_sum = b_sum + bi.into();
    }
    builder.assert_one(b_sum);
    let q33 = cur[COL_EQ33];
    let q49 = cur[COL_EQ49];
    builder.assert_bool(q33);
    builder.assert_bool(q49);
    builder.assert_zero(q33 * q49);
    // 1-block prio: last block is b[0] with q33/q49. Multi-block last ≠ b[0].
    builder.assert_eq(q33 + q49, blast * b[0]);

    let mut h_sum = pad.into();
    let h: Vec<AB::Var> = (0..ENGINE_INSERT_OPENINGS)
        .map(|i| cur[COL_EH + i])
        .collect();
    for &hi in &h {
        builder.assert_bool(hi);
        h_sum = h_sum + hi.into();
    }
    builder.assert_one(h_sum);

    builder.assert_eq(endn, ko * oi[7]);
    builder.assert_eq(wrapn, endn * (AB::Expr::ONE - blast));
    builder.assert_eq(rootn, endn * blast);
    builder.assert_eq(
        wraph,
        rootn * (AB::Expr::ONE - h[ENGINE_INSERT_OPENINGS - 1]),
    );
    builder.assert_eq(nroot, rootn * h[ENGINE_INSERT_OPENINGS - 1]);
    builder.assert_eq(
        cur[COL_BLEN],
        AB::Expr::from(field(64)) * (AB::Expr::ONE - blast)
            + AB::Expr::from(field(33)) * q33
            + AB::Expr::from(field(49)) * q49
            + AB::Expr::from(field(51)) * blast * b[1]
            + AB::Expr::from(field(11)) * blast * b[2]
            + AB::Expr::from(field(24)) * blast * b[3],
    );
    // 1-block: START|END|ROOT; multi first: START; multi last: END|ROOT.
    builder.assert_eq(
        cur[COL_BFLG],
        AB::Expr::from(field(CHUNK_START as u64)) * b[0]
            + AB::Expr::from(field((CHUNK_END | ROOT) as u64)) * blast,
    );
    for i in 0..8 {
        builder.assert_eq(
            cur[COL_NCVO + 2 * i],
            oi[i] * cur[COL_XX] + (AB::Expr::ONE - oi[i]) * cur[COL_NCV + 2 * i],
        );
        builder.assert_eq(
            cur[COL_NCVO + 2 * i + 1],
            oi[i] * cur[COL_XX + 1] + (AB::Expr::ONE - oi[i]) * cur[COL_NCV + 2 * i + 1],
        );
    }

    for k in 0..NODE_DIGEST_BLOCKS {
        let mut bk = builder.when(b[k]);
        for j in 0..32 {
            bk.assert_eq(cur[COL_MSG + j], cur[COL_EPRE + 32 * k + j]);
        }
    }
    for k in 0..NODE_DIGEST_BLOCKS - 1 {
        let mut bk = builder.when(b[k]);
        for j in 0..32 {
            bk.assert_eq(cur[COL_NMSG + j], cur[COL_EPRE + 32 * (k + 1) + j]);
        }
    }
    {
        let mut lastb = builder.when(b[3]);
        for j in 0..32 {
            lastb.assert_zero(cur[COL_NMSG + j]);
        }
    }

    {
        let mut first = builder.when_first_row();
        first.assert_one(kg);
        first.assert_zero(ko);
        first.assert_zero(pad);
        // Chrono may start with 1-block prio (blast = q33+q49).
        first.assert_eq(blast, q33 + q49);
        first.assert_one(gi[0]);
        first.assert_one(rnd[0]);
        first.assert_one(b[0]);
        first.assert_one(h[0]);
        // Init from row BLEN/BFLG so 1-block first opening works.
        let iv4 = [IV[0], IV[1], IV[2], IV[3]];
        for j in 0..8 {
            first.assert_eq(
                cur[COL_S + 2 * j],
                AB::Expr::from(field(lo(IV[j]) as u64)),
            );
            first.assert_eq(
                cur[COL_S + 2 * j + 1],
                AB::Expr::from(field(hi(IV[j]) as u64)),
            );
        }
        for j in 0..4 {
            first.assert_eq(
                cur[COL_S + 16 + 2 * j],
                AB::Expr::from(field(lo(iv4[j]) as u64)),
            );
            first.assert_eq(
                cur[COL_S + 17 + 2 * j],
                AB::Expr::from(field(hi(iv4[j]) as u64)),
            );
        }
        for j in 24..28 {
            first.assert_zero(cur[COL_S + j]);
        }
        first.assert_eq(cur[COL_S + 28], cur[COL_BLEN]);
        first.assert_zero(cur[COL_S + 29]);
        first.assert_eq(cur[COL_S + 30], cur[COL_BFLG]);
        first.assert_zero(cur[COL_S + 31]);
        for i in 0..8 {
            first.assert_eq(
                cur[COL_NCV + 2 * i],
                AB::Expr::from(field(lo(IV[i]) as u64)),
            );
            first.assert_eq(
                cur[COL_NCV + 2 * i + 1],
                AB::Expr::from(field(hi(IV[i]) as u64)),
            );
        }
    }
    {
        let mut last = builder.when_last_row();
        last.assert_one(pad);
        for i in 0..16 {
            last.assert_eq(cur[COL_NCV + i], pis[i]);
        }
    }
    {
        let mut t = builder.when_transition();
        t.assert_eq(nxt[COL_EPAD], pad + nroot);
        t.assert_eq(nxt[COL_KG], kg - lastg + wrapn + wraph);
        t.assert_eq(nxt[COL_KO], lastg + ko * (AB::Expr::ONE - oi[7]));
        t.assert_eq(nxt[COL_GI], stepr + wrapn + wraph);
        for k in 1..8 {
            t.assert_eq(nxt[COL_GI + k], gi[k - 1] * (AB::Expr::ONE - gi[7]));
        }
        t.assert_eq(
            nxt[COL_RND],
            rnd[0] * (AB::Expr::ONE - gi[7]) + wrapn + wraph,
        );
        for r in 1..7 {
            t.assert_eq(
                nxt[COL_RND + r],
                rnd[r] * (AB::Expr::ONE - gi[7]) + rnd[r - 1] * stepr,
            );
        }
        t.assert_eq(nxt[COL_OI], lastg);
        for i in 1..8 {
            t.assert_eq(nxt[COL_OI + i], oi[i - 1] * (AB::Expr::ONE - oi[7]));
        }
        t.assert_eq(nxt[COL_NB], b[0] * (AB::Expr::ONE - endn) + wraph);
        for k in 1..NODE_DIGEST_BLOCKS {
            t.assert_eq(
                nxt[COL_NB + k],
                b[k] * (AB::Expr::ONE - endn) + b[k - 1] * wrapn,
            );
        }
        t.assert_eq(nxt[COL_EH], h[0] * (AB::Expr::ONE - rootn));
        for k in 1..ENGINE_INSERT_OPENINGS {
            t.assert_eq(
                nxt[COL_EH + k],
                h[k] * (AB::Expr::ONE - rootn) + h[k - 1] * wraph,
            );
        }
        t.assert_zero((AB::Expr::ONE - endn) * (nxt[COL_BLAST] - blast));
        // Allow nxt blast=1 on wraph (1-block prio). Multi-block next still
        // starts blast=0 via fill; q33+q49 = blast·b[0] classifies.
        t.assert_zero(nroot * nxt[COL_BLAST]);
        t.assert_zero(pad * nxt[COL_BLAST]);
        t.assert_zero((AB::Expr::ONE - rootn) * (nxt[COL_EQ33] - q33));
        t.assert_zero((AB::Expr::ONE - rootn) * (nxt[COL_EQ49] - q49));
        let iv4 = [IV[0], IV[1], IV[2], IV[3]];
        let next_len = nxt[COL_BLEN];
        let next_flg = nxt[COL_BFLG];
        let wrap = wrapn + wraph;
        for j in 0..8 {
            let iv_lo = AB::Expr::from(field(lo(IV[j]) as u64));
            let iv_hi = AB::Expr::from(field(hi(IV[j]) as u64));
            t.assert_eq(
                nxt[COL_S + 2 * j],
                wrapn * cur[COL_NCVO + 2 * j]
                    + wraph * iv_lo
                    + pad * cur[COL_S + 2 * j]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 2 * j],
            );
            t.assert_eq(
                nxt[COL_S + 2 * j + 1],
                wrapn * cur[COL_NCVO + 2 * j + 1]
                    + wraph * iv_hi
                    + pad * cur[COL_S + 2 * j + 1]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 2 * j + 1],
            );
        }
        for j in 0..4 {
            let iv_lo = AB::Expr::from(field(lo(iv4[j]) as u64));
            let iv_hi = AB::Expr::from(field(hi(iv4[j]) as u64));
            t.assert_eq(
                nxt[COL_S + 16 + 2 * j],
                wrap.clone() * iv_lo
                    + pad * cur[COL_S + 16 + 2 * j]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 16 + 2 * j],
            );
            t.assert_eq(
                nxt[COL_S + 17 + 2 * j],
                wrap.clone() * iv_hi
                    + pad * cur[COL_S + 17 + 2 * j]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 17 + 2 * j],
            );
        }
        for j in 24..28 {
            t.assert_eq(
                nxt[COL_S + j],
                pad * cur[COL_S + j] + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + j],
            );
        }
        // Use next row's BLEN/BFLG so 1-block prio inits with 33/49 + START|END|ROOT.
        t.assert_eq(
            nxt[COL_S + 28],
            wrap.clone() * next_len
                + pad * cur[COL_S + 28]
                + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 28],
        );
        t.assert_eq(
            nxt[COL_S + 29],
            pad * cur[COL_S + 29] + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 29],
        );
        t.assert_eq(
            nxt[COL_S + 30],
            wrap.clone() * next_flg
                + pad * cur[COL_S + 30]
                + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 30],
        );
        t.assert_eq(
            nxt[COL_S + 31],
            pad * cur[COL_S + 31] + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 31],
        );
        for i in 0..16 {
            let iv_limb = if i % 2 == 0 {
                AB::Expr::from(field(lo(IV[i / 2]) as u64))
            } else {
                AB::Expr::from(field(hi(IV[i / 2]) as u64))
            };
            t.assert_eq(
                nxt[COL_NCV + i],
                wraph * iv_limb
                    + pad * cur[COL_NCV + i]
                    + (AB::Expr::ONE - wraph - pad) * cur[COL_NCVO + i],
            );
        }
        for i in 0..32 {
            t.assert_eq(
                nxt[COL_MSG + i],
                wrapn * cur[COL_NMSG + i]
                    + wraph * nxt[COL_EPRE + i]
                    + pad * cur[COL_MSG + i]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_MSG + i],
            );
        }
        for i in 0..128 {
            t.assert_zero((AB::Expr::ONE - wraph) * (nxt[COL_EPRE + i] - cur[COL_EPRE + i]));
        }
        for i in 0..32 {
            t.assert_zero(
                (AB::Expr::ONE - wrapn - wraph) * (nxt[COL_NMSG + i] - cur[COL_NMSG + i]),
            );
        }
    }
    {
        let mut r = builder.when(nroot);
        for i in 0..7 {
            r.assert_eq(cur[COL_NCV + 2 * i], pis[2 * i]);
            r.assert_eq(cur[COL_NCV + 2 * i + 1], pis[2 * i + 1]);
        }
        r.assert_eq(cur[COL_XX], pis[14]);
        r.assert_eq(cur[COL_XX + 1], pis[15]);
    }
    eval_bind_engine_insert_keys(builder, cur, nxt, &h, q33, q49, rootn);
    eval_bind_engine_insert_children(builder, &h, rootn, cur, nxt);
}

/// Order prio hidx 4 → insert-path seen/rest (12+12) key bytes 0..1; owner
/// prio hidx 0 → nonce 1 / 3 + path rest owners; second order prio 38 ↔ oid.
/// Path lists are this fixture's oid-match openings. Not HeightMatch. Not
/// full insert algebra; not `F`.
fn eval_bind_engine_insert_keys<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
    h: &[AB::Var],
    q33: AB::Var,
    q49: AB::Var,
    rootn: AB::Var,
) {
    let pack = AB::Expr::from(field(TAKE_PACK));
    let prio_lo = AB::Expr::from(field(commitments::TREAP_PRIO_DOMAIN[16] as u64));
    let load_oid = cur[COL_EI_LOAD_OID];
    let load_own = cur[COL_EI_LOAD_OWN];
    let chk_oid2 = cur[COL_EI_CHK_OID2];
    builder.assert_bool(load_oid);
    builder.assert_bool(load_own);
    builder.assert_bool(chk_oid2);
    builder.assert_eq(load_oid, q33 * h[EI_HIDX_ORDER_PRIO] * rootn);
    builder.assert_eq(load_own, q49 * h[EI_HIDX_OWNER_PRIO] * rootn);
    builder.assert_eq(chk_oid2, q33 * h[EI_HIDX_ORDER_PRIO2] * rootn);
    let w4 = cur[epre_lo(4)];
    let w4h = cur[epre_lo(4) + 1];
    builder.assert_zero(load_oid * (cur[COL_EI_LAT_OID0] * pack.clone() + prio_lo.clone() - w4.clone()));
    builder.assert_zero(load_oid * (cur[COL_EI_LAT_OID1] - w4h.clone()));
    builder.assert_zero(load_own * (cur[COL_EI_LAT_OWN0] * pack.clone() + prio_lo.clone() - w4.clone()));
    // Second OrderId prio (resting-map) matches latched oid.
    builder.assert_zero(chk_oid2 * (cur[COL_EI_LAT_OID0] * pack.clone() + prio_lo - w4));
    builder.assert_zero(chk_oid2 * (cur[COL_EI_LAT_OID1] - w4h));
    {
        let mut first = builder.when_first_row();
        // Owner prio is opening 0 — may load on row 0.
        first.assert_zero((AB::Expr::ONE - load_own) * cur[COL_EI_LAT_OWN0]);
        first.assert_zero(cur[COL_EI_LAT_OID0]);
        first.assert_zero(cur[COL_EI_LAT_OID1]);
    }
    {
        let mut t = builder.when_transition();
        t.assert_zero(
            (AB::Expr::ONE - nxt[COL_EI_LOAD_OID]) * (nxt[COL_EI_LAT_OID0] - cur[COL_EI_LAT_OID0]),
        );
        t.assert_zero(
            (AB::Expr::ONE - nxt[COL_EI_LOAD_OID]) * (nxt[COL_EI_LAT_OID1] - cur[COL_EI_LAT_OID1]),
        );
        t.assert_zero(
            (AB::Expr::ONE - nxt[COL_EI_LOAD_OWN]) * (nxt[COL_EI_LAT_OWN0] - cur[COL_EI_LAT_OWN0]),
        );
    }
    // Path-wide seen OrderId: align-3 at word 14; byte1 at word 15 lo.
    for &hi in &EI_SEEN_OID_PATH {
        let sel = h[hi] * rootn;
        builder.assert_zero(sel.clone() * (cur[epre_lo(14) + 1] - cur[COL_EI_LAT_OID0] * pack.clone()));
        builder.assert_zero(sel * (cur[epre_lo(15)] - cur[COL_EI_LAT_OID1]));
    }
    // Path-wide resting OrderId + owner (word 32).
    debug_assert_eq!(RESTING_OWNER_OFF, 32 * 4);
    for &hi in &EI_REST_OID_PATH {
        let sel = h[hi] * rootn;
        builder.assert_zero(sel.clone() * (cur[epre_lo(22) + 1] - cur[COL_EI_LAT_OID0] * pack.clone()));
        builder.assert_zero(sel.clone() * (cur[epre_lo(23)] - cur[COL_EI_LAT_OID1]));
        builder.assert_zero(sel * (cur[epre_lo(32)] - cur[COL_EI_LAT_OWN0]));
    }
    let nonce = h[EI_HIDX_NONCE0] * rootn;
    let nonce1 = h[EI_HIDX_NONCE1] * rootn;
    builder.assert_zero(nonce * (cur[epre_lo(14) + 1] - cur[COL_EI_LAT_OWN0] * pack.clone()));
    builder.assert_zero(nonce1 * (cur[epre_lo(14) + 1] - cur[COL_EI_LAT_OWN0] * pack));
}

fn epre_lo(word: usize) -> usize {
    COL_EPRE + 2 * word
}

/// Empty children on insert-path leaves + nonce right; nonce rotate `3←2`;
/// sib fan-outs right←out(6/40/12/46/20/54/24/58), left←…/18/52/22/56/26/60.
/// All insert-path (5..27 / 39..61) sibling outs bound. Upper chain to the
/// roots (28..37 / 62..71) still unbound. Not HeightMatch; not `F`.
fn eval_bind_engine_insert_children<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    h: &[AB::Var],
    rootn: AB::Var,
    cur: &[AB::Var],
    nxt: &[AB::Var],
) {
    debug_assert_eq!(RESTING_LEFT_OFF, 19);
    debug_assert_eq!(SEEN_RIGHT_OFF, 20 * 4 + 3);
    debug_assert_eq!(NONCE_RIGHT_OFF, 26 * 4 + 3);
    debug_assert_eq!(RESTING_RIGHT_OFF, 46 * 4);
    // Empty left: seen 5/7, rest 39/41, nonce 1/2.
    for &hi in &[EI_SEEN_OID_PATH[0], EI_SEEN_OID_PATH[1]] {
        eval_bind_empty_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
        );
    }
    for &hi in &[EI_REST_OID_PATH[0], EI_REST_OID_PATH[1]] {
        eval_bind_empty_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
        );
    }
    for &hi in &[EI_HIDX_NONCE0, EI_HIDX_NONCE_MID] {
        eval_bind_empty_align3_pre(builder, h[hi] * rootn, cur, COL_EPRE, 4, NONCE_KEY_LEN);
    }
    // Empty right: seen leaf, rest leaf, all three nonce.
    eval_bind_empty_align3_pre(
        builder,
        h[EI_SEEN_OID_PATH[0]] * rootn,
        cur,
        COL_EPRE,
        20,
        0,
    );
    eval_bind_empty_words_pre(
        builder,
        h[EI_REST_OID_PATH[0]] * rootn,
        cur,
        COL_EPRE,
        46,
    );
    for &hi in &[EI_HIDX_NONCE0, EI_HIDX_NONCE_MID, EI_HIDX_NONCE1] {
        eval_bind_empty_align3_pre(builder, h[hi] * rootn, cur, COL_EPRE, 26, 0);
    }
    // Nonce rotate: left(3) ← out(2).
    let load_n2 = cur[COL_EI_LOAD_N2];
    builder.assert_bool(load_n2);
    builder.assert_eq(load_n2, h[EI_HIDX_NONCE_MID] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_n2 * (cur[COL_EI_LAT_N2 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_N2 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_N2];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_N2 + i] - cur[COL_EI_LAT_N2 + i]));
        }
    }
    let n2 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_N2..COL_EI_LAT_N2 + 16],
        &cur[COL_EI_N2BIT..COL_EI_N2BIT + 256],
    );
    eval_bind_child_align3_pre(
        builder,
        h[EI_HIDX_NONCE1] * rootn,
        cur,
        COL_EPRE,
        4,
        NONCE_KEY_LEN,
        &n2,
    );
    // Seen sibling fan-out: right(7/9/11) ← out(6) (align-3).
    let load_s6 = cur[COL_EI_LOAD_S6];
    builder.assert_bool(load_s6);
    builder.assert_eq(load_s6, h[EI_HIDX_SEEN_SIB0] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s6 * (cur[COL_EI_LAT_S6 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S6 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S6];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S6 + i] - cur[COL_EI_LAT_S6 + i]));
        }
    }
    let s6 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S6..COL_EI_LAT_S6 + 16],
        &cur[COL_EI_S6BIT..COL_EI_S6BIT + 256],
    );
    for &hi in &EI_SEEN_RIGHT_FROM_SIB0 {
        eval_bind_child_align3_pre(builder, h[hi] * rootn, cur, COL_EPRE, 20, 0, &s6);
    }
    // Rest sibling fan-out: right(41/43/45) ← out(40) (word-aligned limbs).
    let load_r40 = cur[COL_EI_LOAD_R40];
    builder.assert_bool(load_r40);
    builder.assert_eq(load_r40, h[EI_HIDX_REST_SIB0] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r40 * (cur[COL_EI_LAT_R40 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R40 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R40];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R40 + i] - cur[COL_EI_LAT_R40 + i]));
        }
    }
    for &hi in &EI_REST_RIGHT_FROM_SIB0 {
        eval_bind_child_words_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            46,
            &cur[COL_EI_LAT_R40..COL_EI_LAT_R40 + 16],
        );
    }
    // Path node complete: left(9) ← out(8); left(43) ← out(42) (align-3).
    let load_s8 = cur[COL_EI_LOAD_S8];
    builder.assert_bool(load_s8);
    builder.assert_eq(load_s8, h[EI_HIDX_SEEN_SIB1] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s8 * (cur[COL_EI_LAT_S8 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S8 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S8];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S8 + i] - cur[COL_EI_LAT_S8 + i]));
        }
    }
    let s8 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S8..COL_EI_LAT_S8 + 16],
        &cur[COL_EI_S8BIT..COL_EI_S8BIT + 256],
    );
    for &hi in &EI_SEEN_LEFT_FROM_SIB1 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &s8,
        );
    }
    let load_r42 = cur[COL_EI_LOAD_R42];
    builder.assert_bool(load_r42);
    builder.assert_eq(load_r42, h[EI_HIDX_REST_SIB1] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r42 * (cur[COL_EI_LAT_R42 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R42 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R42];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R42 + i] - cur[COL_EI_LAT_R42 + i]));
        }
    }
    let r42 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_R42..COL_EI_LAT_R42 + 16],
        &cur[COL_EI_R42BIT..COL_EI_R42BIT + 256],
    );
    for &hi in &EI_REST_LEFT_FROM_SIB1 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &r42,
        );
    }
    // left(11/13) ← out(10); left(45/47) ← out(44).
    let load_s10 = cur[COL_EI_LOAD_S10];
    builder.assert_bool(load_s10);
    builder.assert_eq(load_s10, h[EI_HIDX_SEEN_SIB2] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s10 * (cur[COL_EI_LAT_S10 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S10 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S10];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S10 + i] - cur[COL_EI_LAT_S10 + i]));
        }
    }
    let s10 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S10..COL_EI_LAT_S10 + 16],
        &cur[COL_EI_S10BIT..COL_EI_S10BIT + 256],
    );
    for &hi in &EI_SEEN_LEFT_FROM_SIB2 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &s10,
        );
    }
    let load_r44 = cur[COL_EI_LOAD_R44];
    builder.assert_bool(load_r44);
    builder.assert_eq(load_r44, h[EI_HIDX_REST_SIB2] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r44 * (cur[COL_EI_LAT_R44 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R44 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R44];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R44 + i] - cur[COL_EI_LAT_R44 + i]));
        }
    }
    let r44 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_R44..COL_EI_LAT_R44 + 16],
        &cur[COL_EI_R44BIT..COL_EI_R44BIT + 256],
    );
    for &hi in &EI_REST_LEFT_FROM_SIB2 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &r44,
        );
    }
    // right(13/15/17/19) ← out(12); right(47/49/51/53) ← out(46).
    let load_s12 = cur[COL_EI_LOAD_S12];
    builder.assert_bool(load_s12);
    builder.assert_eq(load_s12, h[EI_HIDX_SEEN_SIB3] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s12 * (cur[COL_EI_LAT_S12 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S12 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S12];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S12 + i] - cur[COL_EI_LAT_S12 + i]));
        }
    }
    let s12 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S12..COL_EI_LAT_S12 + 16],
        &cur[COL_EI_S12BIT..COL_EI_S12BIT + 256],
    );
    for &hi in &EI_SEEN_RIGHT_FROM_SIB3 {
        eval_bind_child_align3_pre(builder, h[hi] * rootn, cur, COL_EPRE, 20, 0, &s12);
    }
    let load_r46 = cur[COL_EI_LOAD_R46];
    builder.assert_bool(load_r46);
    builder.assert_eq(load_r46, h[EI_HIDX_REST_SIB3] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r46 * (cur[COL_EI_LAT_R46 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R46 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R46];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R46 + i] - cur[COL_EI_LAT_R46 + i]));
        }
    }
    for &hi in &EI_REST_RIGHT_FROM_SIB3 {
        eval_bind_child_words_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            46,
            &cur[COL_EI_LAT_R46..COL_EI_LAT_R46 + 16],
        );
    }
    // left(15) ← out(14); left(49) ← out(48).
    let load_s14 = cur[COL_EI_LOAD_S14];
    builder.assert_bool(load_s14);
    builder.assert_eq(load_s14, h[EI_HIDX_SEEN_SIB4] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s14 * (cur[COL_EI_LAT_S14 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S14 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S14];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S14 + i] - cur[COL_EI_LAT_S14 + i]));
        }
    }
    let s14 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S14..COL_EI_LAT_S14 + 16],
        &cur[COL_EI_S14BIT..COL_EI_S14BIT + 256],
    );
    for &hi in &EI_SEEN_LEFT_FROM_SIB4 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &s14,
        );
    }
    let load_r48 = cur[COL_EI_LOAD_R48];
    builder.assert_bool(load_r48);
    builder.assert_eq(load_r48, h[EI_HIDX_REST_SIB4] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r48 * (cur[COL_EI_LAT_R48 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R48 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R48];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R48 + i] - cur[COL_EI_LAT_R48 + i]));
        }
    }
    let r48 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_R48..COL_EI_LAT_R48 + 16],
        &cur[COL_EI_R48BIT..COL_EI_R48BIT + 256],
    );
    for &hi in &EI_REST_LEFT_FROM_SIB4 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &r48,
        );
    }
    // left(17) ← out(16); left(51) ← out(50).
    let load_s16 = cur[COL_EI_LOAD_S16];
    builder.assert_bool(load_s16);
    builder.assert_eq(load_s16, h[EI_HIDX_SEEN_SIB5] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s16 * (cur[COL_EI_LAT_S16 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S16 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S16];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S16 + i] - cur[COL_EI_LAT_S16 + i]));
        }
    }
    let s16 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S16..COL_EI_LAT_S16 + 16],
        &cur[COL_EI_S16BIT..COL_EI_S16BIT + 256],
    );
    for &hi in &EI_SEEN_LEFT_FROM_SIB5 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &s16,
        );
    }
    let load_r50 = cur[COL_EI_LOAD_R50];
    builder.assert_bool(load_r50);
    builder.assert_eq(load_r50, h[EI_HIDX_REST_SIB5] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r50 * (cur[COL_EI_LAT_R50 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R50 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R50];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R50 + i] - cur[COL_EI_LAT_R50 + i]));
        }
    }
    let r50 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_R50..COL_EI_LAT_R50 + 16],
        &cur[COL_EI_R50BIT..COL_EI_R50BIT + 256],
    );
    for &hi in &EI_REST_LEFT_FROM_SIB5 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &r50,
        );
    }
    // left(19/21) ← out(18); left(53/55) ← out(52).
    let load_s18 = cur[COL_EI_LOAD_S18];
    builder.assert_bool(load_s18);
    builder.assert_eq(load_s18, h[EI_HIDX_SEEN_SIB6] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s18 * (cur[COL_EI_LAT_S18 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S18 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S18];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S18 + i] - cur[COL_EI_LAT_S18 + i]));
        }
    }
    let s18 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S18..COL_EI_LAT_S18 + 16],
        &cur[COL_EI_S18BIT..COL_EI_S18BIT + 256],
    );
    for &hi in &EI_SEEN_LEFT_FROM_SIB6 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &s18,
        );
    }
    let load_r52 = cur[COL_EI_LOAD_R52];
    builder.assert_bool(load_r52);
    builder.assert_eq(load_r52, h[EI_HIDX_REST_SIB6] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r52 * (cur[COL_EI_LAT_R52 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R52 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R52];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R52 + i] - cur[COL_EI_LAT_R52 + i]));
        }
    }
    let r52 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_R52..COL_EI_LAT_R52 + 16],
        &cur[COL_EI_R52BIT..COL_EI_R52BIT + 256],
    );
    for &hi in &EI_REST_LEFT_FROM_SIB6 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &r52,
        );
    }
    // right(21/23) ← out(20); right(55/57) ← out(54).
    let load_s20 = cur[COL_EI_LOAD_S20];
    builder.assert_bool(load_s20);
    builder.assert_eq(load_s20, h[EI_HIDX_SEEN_SIB7] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s20 * (cur[COL_EI_LAT_S20 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S20 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S20];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S20 + i] - cur[COL_EI_LAT_S20 + i]));
        }
    }
    let s20 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S20..COL_EI_LAT_S20 + 16],
        &cur[COL_EI_S20BIT..COL_EI_S20BIT + 256],
    );
    for &hi in &EI_SEEN_RIGHT_FROM_SIB7 {
        eval_bind_child_align3_pre(builder, h[hi] * rootn, cur, COL_EPRE, 20, 0, &s20);
    }
    let load_r54 = cur[COL_EI_LOAD_R54];
    builder.assert_bool(load_r54);
    builder.assert_eq(load_r54, h[EI_HIDX_REST_SIB7] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r54 * (cur[COL_EI_LAT_R54 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R54 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R54];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R54 + i] - cur[COL_EI_LAT_R54 + i]));
        }
    }
    for &hi in &EI_REST_RIGHT_FROM_SIB7 {
        eval_bind_child_words_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            46,
            &cur[COL_EI_LAT_R54..COL_EI_LAT_R54 + 16],
        );
    }
    // left(23/25) ← out(22); left(57/59) ← out(56).
    let load_s22 = cur[COL_EI_LOAD_S22];
    builder.assert_bool(load_s22);
    builder.assert_eq(load_s22, h[EI_HIDX_SEEN_SIB8] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s22 * (cur[COL_EI_LAT_S22 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S22 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S22];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S22 + i] - cur[COL_EI_LAT_S22 + i]));
        }
    }
    let s22 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S22..COL_EI_LAT_S22 + 16],
        &cur[COL_EI_S22BIT..COL_EI_S22BIT + 256],
    );
    for &hi in &EI_SEEN_LEFT_FROM_SIB8 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &s22,
        );
    }
    let load_r56 = cur[COL_EI_LOAD_R56];
    builder.assert_bool(load_r56);
    builder.assert_eq(load_r56, h[EI_HIDX_REST_SIB8] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r56 * (cur[COL_EI_LAT_R56 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R56 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R56];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R56 + i] - cur[COL_EI_LAT_R56 + i]));
        }
    }
    let r56 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_R56..COL_EI_LAT_R56 + 16],
        &cur[COL_EI_R56BIT..COL_EI_R56BIT + 256],
    );
    for &hi in &EI_REST_LEFT_FROM_SIB8 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &r56,
        );
    }
    // right(25/27) ← out(24); right(59/61) ← out(58).
    let load_s24 = cur[COL_EI_LOAD_S24];
    builder.assert_bool(load_s24);
    builder.assert_eq(load_s24, h[EI_HIDX_SEEN_SIB9] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s24 * (cur[COL_EI_LAT_S24 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S24 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S24];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S24 + i] - cur[COL_EI_LAT_S24 + i]));
        }
    }
    let s24 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S24..COL_EI_LAT_S24 + 16],
        &cur[COL_EI_S24BIT..COL_EI_S24BIT + 256],
    );
    for &hi in &EI_SEEN_RIGHT_FROM_SIB9 {
        eval_bind_child_align3_pre(builder, h[hi] * rootn, cur, COL_EPRE, 20, 0, &s24);
    }
    let load_r58 = cur[COL_EI_LOAD_R58];
    builder.assert_bool(load_r58);
    builder.assert_eq(load_r58, h[EI_HIDX_REST_SIB9] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r58 * (cur[COL_EI_LAT_R58 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R58 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R58];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R58 + i] - cur[COL_EI_LAT_R58 + i]));
        }
    }
    for &hi in &EI_REST_RIGHT_FROM_SIB9 {
        eval_bind_child_words_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            46,
            &cur[COL_EI_LAT_R58..COL_EI_LAT_R58 + 16],
        );
    }
    // left(27) ← out(26); left(61) ← out(60).
    let load_s26 = cur[COL_EI_LOAD_S26];
    builder.assert_bool(load_s26);
    builder.assert_eq(load_s26, h[EI_HIDX_SEEN_SIB10] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_s26 * (cur[COL_EI_LAT_S26 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_S26 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_S26];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_S26 + i] - cur[COL_EI_LAT_S26 + i]));
        }
    }
    let s26 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_S26..COL_EI_LAT_S26 + 16],
        &cur[COL_EI_S26BIT..COL_EI_S26BIT + 256],
    );
    for &hi in &EI_SEEN_LEFT_FROM_SIB10 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &s26,
        );
    }
    let load_r60 = cur[COL_EI_LOAD_R60];
    builder.assert_bool(load_r60);
    builder.assert_eq(load_r60, h[EI_HIDX_REST_SIB10] * rootn);
    for i in 0..16 {
        builder.assert_zero(load_r60 * (cur[COL_EI_LAT_R60 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_EI_LAT_R60 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_EI_LOAD_R60];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_EI_LAT_R60 + i] - cur[COL_EI_LAT_R60 + i]));
        }
    }
    let r60 = eval_digest_bytes(
        builder,
        &cur[COL_EI_LAT_R60..COL_EI_LAT_R60 + 16],
        &cur[COL_EI_R60BIT..COL_EI_R60BIT + 256],
    );
    for &hi in &EI_REST_LEFT_FROM_SIB10 {
        eval_bind_child_align3_pre(
            builder,
            h[hi] * rootn,
            cur,
            COL_EPRE,
            4,
            RESTING_KEY_LEN,
            &r60,
        );
    }
}

fn generate_engine_insert_trace(preimages: &[Vec<u8>]) -> RowMajorMatrix<Val> {
    assert_eq!(preimages.len(), ENGINE_INSERT_OPENINGS);
    let mut values = vec![Val::ZERO; EI_ROWS * EI_WIDTH];
    let mut row_off = 0usize;
    let mut last_dig = [0u32; 8];
    let mut lat_oid0 = Val::ZERO;
    let mut lat_oid1 = Val::ZERO;
    let mut lat_own0 = Val::ZERO;
    let mut lat_n2 = [Val::ZERO; 16];
    let mut lat_s6 = [Val::ZERO; 16];
    let mut lat_r40 = [Val::ZERO; 16];
    let mut lat_s8 = [Val::ZERO; 16];
    let mut lat_r42 = [Val::ZERO; 16];
    let mut lat_s10 = [Val::ZERO; 16];
    let mut lat_r44 = [Val::ZERO; 16];
    let mut lat_s12 = [Val::ZERO; 16];
    let mut lat_r46 = [Val::ZERO; 16];
    let mut lat_s14 = [Val::ZERO; 16];
    let mut lat_r48 = [Val::ZERO; 16];
    let mut lat_s16 = [Val::ZERO; 16];
    let mut lat_r50 = [Val::ZERO; 16];
    let mut lat_s18 = [Val::ZERO; 16];
    let mut lat_r52 = [Val::ZERO; 16];
    let mut lat_s20 = [Val::ZERO; 16];
    let mut lat_r54 = [Val::ZERO; 16];
    let mut lat_s22 = [Val::ZERO; 16];
    let mut lat_r56 = [Val::ZERO; 16];
    let mut lat_s24 = [Val::ZERO; 16];
    let mut lat_r58 = [Val::ZERO; 16];
    let mut lat_s26 = [Val::ZERO; 16];
    let mut lat_r60 = [Val::ZERO; 16];
    for (h, pre) in preimages.iter().enumerate() {
        let nblocks = opening_nblocks(pre.len());
        assert!(matches!(
            pre.len(),
            SEEN_NODE_BYTES
                | NONCE_NODE_BYTES
                | RESTING_NODE_BYTES
                | PRIO_ORDER_BYTES
                | PRIO_OWNER_BYTES
        ));
        let words = padded_msg_words_n(pre);
        last_dig = words32(&blake3_hash_msg(pre));
        fill_opening_n_cols(&mut values, EI_WIDTH, row_off, pre);
        let q33 = pre.len() == PRIO_ORDER_BYTES;
        let q49 = pre.len() == PRIO_OWNER_BYTES;
        let is_oid_prio = q33 && h == EI_HIDX_ORDER_PRIO;
        let is_own_prio = q49 && h == EI_HIDX_OWNER_PRIO;
        for r in 0..nblocks * C_ROWS {
            let row = &mut values[(row_off + r) * EI_WIDTH..(row_off + r + 1) * EI_WIDTH];
            row[COL_EH + h] = Val::ONE;
            put_words64(row, COL_EPRE, &words);
            let bi = r / C_ROWS;
            let last_block = bi + 1 == nblocks;
            if last_block {
                row[COL_BLAST] = Val::ONE;
            }
            if q33 {
                row[COL_EQ33] = Val::ONE;
            }
            if q49 {
                row[COL_EQ49] = Val::ONE;
            }
            let (blen, flags) = opening_block_len_flags(bi, nblocks, pre.len());
            row[COL_BLEN] = field(blen as u64);
            row[COL_BFLG] = field(flags as u64);
            let root_row = r + 1 == nblocks * C_ROWS;
            if root_row {
                if h + 1 < ENGINE_INSERT_OPENINGS {
                    row[COL_EWRAP] = Val::ONE;
                } else {
                    row[COL_EROOT] = Val::ONE;
                }
                if is_oid_prio {
                    row[COL_EI_LOAD_OID] = Val::ONE;
                    lat_oid0 = field(pre[17] as u64);
                    lat_oid1 = field(u16::from_le_bytes([pre[18], pre[19]]) as u64);
                }
                if is_own_prio {
                    row[COL_EI_LOAD_OWN] = Val::ONE;
                    lat_own0 = field(pre[17] as u64);
                }
                if q33 && h == EI_HIDX_ORDER_PRIO2 {
                    row[COL_EI_CHK_OID2] = Val::ONE;
                }
                if h == EI_HIDX_NONCE_MID {
                    row[COL_EI_LOAD_N2] = Val::ONE;
                    lat_n2.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB0 {
                    row[COL_EI_LOAD_S6] = Val::ONE;
                    lat_s6.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB0 {
                    row[COL_EI_LOAD_R40] = Val::ONE;
                    lat_r40.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB1 {
                    row[COL_EI_LOAD_S8] = Val::ONE;
                    lat_s8.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB1 {
                    row[COL_EI_LOAD_R42] = Val::ONE;
                    lat_r42.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB2 {
                    row[COL_EI_LOAD_S10] = Val::ONE;
                    lat_s10.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB2 {
                    row[COL_EI_LOAD_R44] = Val::ONE;
                    lat_r44.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB3 {
                    row[COL_EI_LOAD_S12] = Val::ONE;
                    lat_s12.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB3 {
                    row[COL_EI_LOAD_R46] = Val::ONE;
                    lat_r46.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB4 {
                    row[COL_EI_LOAD_S14] = Val::ONE;
                    lat_s14.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB4 {
                    row[COL_EI_LOAD_R48] = Val::ONE;
                    lat_r48.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB5 {
                    row[COL_EI_LOAD_S16] = Val::ONE;
                    lat_s16.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB5 {
                    row[COL_EI_LOAD_R50] = Val::ONE;
                    lat_r50.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB6 {
                    row[COL_EI_LOAD_S18] = Val::ONE;
                    lat_s18.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB6 {
                    row[COL_EI_LOAD_R52] = Val::ONE;
                    lat_r52.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB7 {
                    row[COL_EI_LOAD_S20] = Val::ONE;
                    lat_s20.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB7 {
                    row[COL_EI_LOAD_R54] = Val::ONE;
                    lat_r54.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB8 {
                    row[COL_EI_LOAD_S22] = Val::ONE;
                    lat_s22.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB8 {
                    row[COL_EI_LOAD_R56] = Val::ONE;
                    lat_r56.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB9 {
                    row[COL_EI_LOAD_S24] = Val::ONE;
                    lat_s24.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB9 {
                    row[COL_EI_LOAD_R58] = Val::ONE;
                    lat_r58.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_SEEN_SIB10 {
                    row[COL_EI_LOAD_S26] = Val::ONE;
                    lat_s26.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
                if h == EI_HIDX_REST_SIB10 {
                    row[COL_EI_LOAD_R60] = Val::ONE;
                    lat_r60.copy_from_slice(&row[COL_NCVO..COL_NCVO + 16]);
                }
            }
            row[COL_EI_LAT_OID0] = lat_oid0;
            row[COL_EI_LAT_OID1] = lat_oid1;
            row[COL_EI_LAT_OWN0] = lat_own0;
            row[COL_EI_LAT_N2..COL_EI_LAT_N2 + 16].copy_from_slice(&lat_n2);
            fill_limb_bits(row, COL_EI_N2BIT, &lat_n2);
            row[COL_EI_LAT_S6..COL_EI_LAT_S6 + 16].copy_from_slice(&lat_s6);
            fill_limb_bits(row, COL_EI_S6BIT, &lat_s6);
            row[COL_EI_LAT_R40..COL_EI_LAT_R40 + 16].copy_from_slice(&lat_r40);
            row[COL_EI_LAT_S8..COL_EI_LAT_S8 + 16].copy_from_slice(&lat_s8);
            fill_limb_bits(row, COL_EI_S8BIT, &lat_s8);
            row[COL_EI_LAT_R42..COL_EI_LAT_R42 + 16].copy_from_slice(&lat_r42);
            fill_limb_bits(row, COL_EI_R42BIT, &lat_r42);
            row[COL_EI_LAT_S10..COL_EI_LAT_S10 + 16].copy_from_slice(&lat_s10);
            fill_limb_bits(row, COL_EI_S10BIT, &lat_s10);
            row[COL_EI_LAT_R44..COL_EI_LAT_R44 + 16].copy_from_slice(&lat_r44);
            fill_limb_bits(row, COL_EI_R44BIT, &lat_r44);
            row[COL_EI_LAT_S12..COL_EI_LAT_S12 + 16].copy_from_slice(&lat_s12);
            fill_limb_bits(row, COL_EI_S12BIT, &lat_s12);
            row[COL_EI_LAT_R46..COL_EI_LAT_R46 + 16].copy_from_slice(&lat_r46);
            row[COL_EI_LAT_S14..COL_EI_LAT_S14 + 16].copy_from_slice(&lat_s14);
            fill_limb_bits(row, COL_EI_S14BIT, &lat_s14);
            row[COL_EI_LAT_R48..COL_EI_LAT_R48 + 16].copy_from_slice(&lat_r48);
            fill_limb_bits(row, COL_EI_R48BIT, &lat_r48);
            row[COL_EI_LAT_S16..COL_EI_LAT_S16 + 16].copy_from_slice(&lat_s16);
            fill_limb_bits(row, COL_EI_S16BIT, &lat_s16);
            row[COL_EI_LAT_R50..COL_EI_LAT_R50 + 16].copy_from_slice(&lat_r50);
            fill_limb_bits(row, COL_EI_R50BIT, &lat_r50);
            row[COL_EI_LAT_S18..COL_EI_LAT_S18 + 16].copy_from_slice(&lat_s18);
            fill_limb_bits(row, COL_EI_S18BIT, &lat_s18);
            row[COL_EI_LAT_R52..COL_EI_LAT_R52 + 16].copy_from_slice(&lat_r52);
            fill_limb_bits(row, COL_EI_R52BIT, &lat_r52);
            row[COL_EI_LAT_S20..COL_EI_LAT_S20 + 16].copy_from_slice(&lat_s20);
            fill_limb_bits(row, COL_EI_S20BIT, &lat_s20);
            row[COL_EI_LAT_R54..COL_EI_LAT_R54 + 16].copy_from_slice(&lat_r54);
            row[COL_EI_LAT_S22..COL_EI_LAT_S22 + 16].copy_from_slice(&lat_s22);
            fill_limb_bits(row, COL_EI_S22BIT, &lat_s22);
            row[COL_EI_LAT_R56..COL_EI_LAT_R56 + 16].copy_from_slice(&lat_r56);
            fill_limb_bits(row, COL_EI_R56BIT, &lat_r56);
            row[COL_EI_LAT_S24..COL_EI_LAT_S24 + 16].copy_from_slice(&lat_s24);
            fill_limb_bits(row, COL_EI_S24BIT, &lat_s24);
            row[COL_EI_LAT_R58..COL_EI_LAT_R58 + 16].copy_from_slice(&lat_r58);
            row[COL_EI_LAT_S26..COL_EI_LAT_S26 + 16].copy_from_slice(&lat_s26);
            fill_limb_bits(row, COL_EI_S26BIT, &lat_s26);
            row[COL_EI_LAT_R60..COL_EI_LAT_R60 + 16].copy_from_slice(&lat_r60);
            fill_limb_bits(row, COL_EI_R60BIT, &lat_r60);
        }
        row_off += nblocks * C_ROWS;
    }
    let active = row_off;
    assert!(active < EI_ROWS);
    let last = values[(active - 1) * EI_WIDTH..active * EI_WIDTH].to_vec();
    for i in active..EI_ROWS {
        let row = &mut values[i * EI_WIDTH..(i + 1) * EI_WIDTH];
        fill_g_columns(
            row,
            Blake3G {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                x: 0,
                y: 0,
            },
        );
        row[COL_S..COL_S + 32].copy_from_slice(&last[COL_S..COL_S + 32]);
        row[COL_SO..COL_SO + 32].copy_from_slice(&last[COL_SO..COL_SO + 32]);
        row[COL_MSG..COL_MSG + 32].copy_from_slice(&last[COL_MSG..COL_MSG + 32]);
        row[COL_EPRE..COL_EPRE + 128].copy_from_slice(&last[COL_EPRE..COL_EPRE + 128]);
        row[COL_EPAD] = Val::ONE;
        row[COL_BLEN] = field(64);
        row[COL_EI_LAT_OID0] = last[COL_EI_LAT_OID0];
        row[COL_EI_LAT_OID1] = last[COL_EI_LAT_OID1];
        row[COL_EI_LAT_OWN0] = last[COL_EI_LAT_OWN0];
        row[COL_EI_LAT_N2..COL_EI_LAT_N2 + 16]
            .copy_from_slice(&last[COL_EI_LAT_N2..COL_EI_LAT_N2 + 16]);
        row[COL_EI_N2BIT..COL_EI_N2BIT + 256]
            .copy_from_slice(&last[COL_EI_N2BIT..COL_EI_N2BIT + 256]);
        row[COL_EI_LAT_S6..COL_EI_LAT_S6 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S6..COL_EI_LAT_S6 + 16]);
        row[COL_EI_S6BIT..COL_EI_S6BIT + 256]
            .copy_from_slice(&last[COL_EI_S6BIT..COL_EI_S6BIT + 256]);
        row[COL_EI_LAT_R40..COL_EI_LAT_R40 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R40..COL_EI_LAT_R40 + 16]);
        row[COL_EI_LAT_S8..COL_EI_LAT_S8 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S8..COL_EI_LAT_S8 + 16]);
        row[COL_EI_S8BIT..COL_EI_S8BIT + 256]
            .copy_from_slice(&last[COL_EI_S8BIT..COL_EI_S8BIT + 256]);
        row[COL_EI_LAT_R42..COL_EI_LAT_R42 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R42..COL_EI_LAT_R42 + 16]);
        row[COL_EI_R42BIT..COL_EI_R42BIT + 256]
            .copy_from_slice(&last[COL_EI_R42BIT..COL_EI_R42BIT + 256]);
        row[COL_EI_LAT_S10..COL_EI_LAT_S10 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S10..COL_EI_LAT_S10 + 16]);
        row[COL_EI_S10BIT..COL_EI_S10BIT + 256]
            .copy_from_slice(&last[COL_EI_S10BIT..COL_EI_S10BIT + 256]);
        row[COL_EI_LAT_R44..COL_EI_LAT_R44 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R44..COL_EI_LAT_R44 + 16]);
        row[COL_EI_R44BIT..COL_EI_R44BIT + 256]
            .copy_from_slice(&last[COL_EI_R44BIT..COL_EI_R44BIT + 256]);
        row[COL_EI_LAT_S12..COL_EI_LAT_S12 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S12..COL_EI_LAT_S12 + 16]);
        row[COL_EI_S12BIT..COL_EI_S12BIT + 256]
            .copy_from_slice(&last[COL_EI_S12BIT..COL_EI_S12BIT + 256]);
        row[COL_EI_LAT_R46..COL_EI_LAT_R46 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R46..COL_EI_LAT_R46 + 16]);
        row[COL_EI_LAT_S14..COL_EI_LAT_S14 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S14..COL_EI_LAT_S14 + 16]);
        row[COL_EI_S14BIT..COL_EI_S14BIT + 256]
            .copy_from_slice(&last[COL_EI_S14BIT..COL_EI_S14BIT + 256]);
        row[COL_EI_LAT_R48..COL_EI_LAT_R48 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R48..COL_EI_LAT_R48 + 16]);
        row[COL_EI_R48BIT..COL_EI_R48BIT + 256]
            .copy_from_slice(&last[COL_EI_R48BIT..COL_EI_R48BIT + 256]);
        row[COL_EI_LAT_S16..COL_EI_LAT_S16 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S16..COL_EI_LAT_S16 + 16]);
        row[COL_EI_S16BIT..COL_EI_S16BIT + 256]
            .copy_from_slice(&last[COL_EI_S16BIT..COL_EI_S16BIT + 256]);
        row[COL_EI_LAT_R50..COL_EI_LAT_R50 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R50..COL_EI_LAT_R50 + 16]);
        row[COL_EI_R50BIT..COL_EI_R50BIT + 256]
            .copy_from_slice(&last[COL_EI_R50BIT..COL_EI_R50BIT + 256]);
        row[COL_EI_LAT_S18..COL_EI_LAT_S18 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S18..COL_EI_LAT_S18 + 16]);
        row[COL_EI_S18BIT..COL_EI_S18BIT + 256]
            .copy_from_slice(&last[COL_EI_S18BIT..COL_EI_S18BIT + 256]);
        row[COL_EI_LAT_R52..COL_EI_LAT_R52 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R52..COL_EI_LAT_R52 + 16]);
        row[COL_EI_R52BIT..COL_EI_R52BIT + 256]
            .copy_from_slice(&last[COL_EI_R52BIT..COL_EI_R52BIT + 256]);
        row[COL_EI_LAT_S20..COL_EI_LAT_S20 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S20..COL_EI_LAT_S20 + 16]);
        row[COL_EI_S20BIT..COL_EI_S20BIT + 256]
            .copy_from_slice(&last[COL_EI_S20BIT..COL_EI_S20BIT + 256]);
        row[COL_EI_LAT_R54..COL_EI_LAT_R54 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R54..COL_EI_LAT_R54 + 16]);
        row[COL_EI_LAT_S22..COL_EI_LAT_S22 + 16]
            .copy_from_slice(&last[COL_EI_LAT_S22..COL_EI_LAT_S22 + 16]);
        row[COL_EI_S22BIT..COL_EI_S22BIT + 256]
            .copy_from_slice(&last[COL_EI_S22BIT..COL_EI_S22BIT + 256]);
        row[COL_EI_LAT_R56..COL_EI_LAT_R56 + 16]
            .copy_from_slice(&last[COL_EI_LAT_R56..COL_EI_LAT_R56 + 16]);
        row[COL_EI_R56BIT..COL_EI_R56BIT + 256]
            .copy_from_slice(&last[COL_EI_R56BIT..COL_EI_R56BIT + 256]);
        row[COL_EI_LAT_S24..COL_EI_R60BIT + 256]
            .copy_from_slice(&last[COL_EI_LAT_S24..COL_EI_R60BIT + 256]);
        put_words8(row, COL_NCV, &last_dig);
        put_words8(row, COL_NCVO, &last_dig);
    }
    RowMajorMatrix::new(values, EI_WIDTH)
}

fn public_engine_insert(preimages: &[Vec<u8>]) -> [Val; EI_PIS] {
    let last = blake3_hash_msg(preimages.last().expect("openings"));
    let dw = words32(&last);
    let mut pis = [Val::ZERO; EI_PIS];
    for i in 0..8 {
        pis[2 * i] = field(lo(dw[i]) as u64);
        pis[2 * i + 1] = field(hi(dw[i]) as u64);
    }
    pis
}

#[derive(Clone, Debug)]
pub struct EngineInsertProof {
    pub bytes: Vec<u8>,
}

pub fn prove_engine_insert_with(
    preimages: Vec<Vec<u8>>,
    class: FriClass,
) -> Result<EngineInsertProof, ProveError> {
    let config = make_config(class);
    let trace = generate_engine_insert_trace(&preimages);
    let pis = public_engine_insert(&preimages);
    let proof = prove(&config, &EngineInsertAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(EngineInsertProof { bytes })
}

pub fn verify_engine_insert_with(
    preimages: Vec<Vec<u8>>,
    proof: &EngineInsertProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_engine_insert(&preimages);
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &EngineInsertAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_engine_insert_and_report_with(
    preimages: Vec<Vec<u8>>,
    class: FriClass,
) -> Result<(EngineInsertProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_engine_insert_with(preimages.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_engine_insert_with(preimages, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

fn tape_hidx_flags(h: usize, n: usize) -> (Val, Val, Val) {
    let last = n - 1;
    let hidx = field(h as u64);
    if h == last {
        (hidx, Val::ONE, Val::ZERO)
    } else {
        (hidx, Val::ZERO, (hidx - field(last as u64)).inverse())
    }
}

/// Eight mixed events on an 8k book: 281 chronological openings (269 node +
/// 12 prio interleaved via `start_c_prime_trace`). Not one Place (72), not
/// HeightMatch (19), not 8 scan proofs, not 10k `F`.
pub struct EngineTapeAir;

fn mixed_openings_next_cols() -> Vec<usize> {
    let mut cols: Vec<usize> = (COL_S..COL_S + 32).collect();
    cols.extend(COL_SO..COL_SO + 32);
    cols.extend(COL_GI..COL_GI + 8);
    cols.extend(COL_RND..COL_RND + 7);
    cols.push(COL_KG);
    cols.push(COL_KO);
    cols.extend(COL_OI..COL_OI + 8);
    cols.push(COL_STEPR);
    cols.push(COL_LASTG);
    cols.extend(COL_MSG..COL_MSG + 32);
    cols.extend(COL_NB..COL_NB + NODE_DIGEST_BLOCKS);
    cols.push(COL_ENDN);
    cols.push(COL_WRAPN);
    cols.push(COL_ROOTN);
    cols.extend(COL_NCV..COL_NCV + 16);
    cols.extend(COL_NCVO..COL_NCVO + 16);
    cols.extend(COL_NMSG..COL_NMSG + 32);
    cols.push(COL_BLAST);
    cols.push(COL_BLEN);
    cols.push(COL_BFLG);
    cols.push(COL_HIDX);
    cols.push(COL_HLAST);
    cols.push(COL_HINV);
    cols.push(COL_TPAD);
    cols.push(COL_TWRAP);
    cols.push(COL_TROOT);
    cols.extend(COL_TPRE..COL_TPRE + 128);
    cols
}

fn mixed_openings_one_block_next_cols() -> Vec<usize> {
    let mut cols = mixed_openings_next_cols();
    cols.push(COL_Q33);
    cols.push(COL_Q49);
    cols.push(COL_Q24);
    cols.push(COL_Q41);
    cols.push(COL_Q52);
    cols.push(COL_Q21);
    cols.push(COL_NB4);
    cols.push(COL_B3N);
    cols.extend(COL_TPRE5..COL_TPRE5 + 32);
    cols
}

impl<F> BaseAir<F> for EngineTapeAir {
    fn width(&self) -> usize {
        H_WIDTH
    }

    fn num_public_values(&self) -> usize {
        T_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        mixed_openings_one_block_next_cols()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for EngineTapeAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; T_PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..H_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..H_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };
        eval_engine_tape(builder, &cur, &nxt, &pis, ENGINE_TAPE_OPENINGS, true);
    }
}

/// Fourteen chronological `C'` hashes of the two-place `HeightStatement`
/// height (prio interleaved with nodes via `start_c_prime_trace`). PIs are
/// the last digest, not `post_root`. Not `F`. Not matching.
pub struct HeightOpeningsAir;

impl<F> BaseAir<F> for HeightOpeningsAir {
    fn width(&self) -> usize {
        H_WIDTH
    }

    fn num_public_values(&self) -> usize {
        T_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        mixed_openings_one_block_next_cols()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for HeightOpeningsAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: [AB::PublicVar; T_PIS] = std::array::from_fn(|i| pv[i]);
            let cur: Vec<AB::Var> = (0..H_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..H_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };
        eval_engine_tape(builder, &cur, &nxt, &pis, HEIGHT_OPENINGS, true);
    }
}

fn eval_engine_tape<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
    pis: &[AB::PublicVar],
    n_openings: usize,
    one_block: bool,
) {
    let kg = cur[COL_KG];
    let ko = cur[COL_KO];
    let pad = cur[COL_TPAD];
    let stepr = cur[COL_STEPR];
    let lastg = cur[COL_LASTG];
    let endn = cur[COL_ENDN];
    let wrapn = cur[COL_WRAPN];
    let rootn = cur[COL_ROOTN];
    let blast = cur[COL_BLAST];
    let hlast = cur[COL_HLAST];
    let hinv = cur[COL_HINV];
    let hidx = cur[COL_HIDX];
    let wraph = cur[COL_TWRAP];
    let nroot = cur[COL_TROOT];
    builder.assert_bool(pad);
    builder.assert_bool(endn);
    builder.assert_bool(wrapn);
    builder.assert_bool(rootn);
    builder.assert_bool(blast);
    builder.assert_bool(hlast);
    builder.assert_bool(wraph);
    builder.assert_bool(nroot);
    builder.assert_one(kg + ko + pad);
    builder.assert_zero(kg * ko);
    builder.assert_zero(kg * pad);
    builder.assert_zero(ko * pad);

    let (gi, rnd, oi) = eval_compress_gadget(builder, &cur);

    let mut b_sum = pad.into();
    let b: Vec<AB::Var> = (0..NODE_DIGEST_BLOCKS).map(|i| cur[COL_NB + i]).collect();
    for &bi in &b {
        builder.assert_bool(bi);
        b_sum = b_sum + bi.into();
    }
    if one_block {
        builder.assert_bool(cur[COL_NB4]);
        b_sum = b_sum + cur[COL_NB4].into();
    }
    builder.assert_one(b_sum);
    let q33 = if one_block {
        builder.assert_bool(cur[COL_Q33]);
        builder.assert_bool(cur[COL_Q49]);
        builder.assert_zero(cur[COL_Q33] * cur[COL_Q49]);
        builder.assert_eq(cur[COL_Q33] + cur[COL_Q49], blast * b[0]);
        cur[COL_Q33].into()
    } else {
        builder.assert_zero(blast * b[0]);
        AB::Expr::ZERO
    };
    let q49 = if one_block {
        cur[COL_Q49].into()
    } else {
        AB::Expr::ZERO
    };
    let q24 = if one_block {
        builder.assert_bool(cur[COL_Q24]);
        builder.assert_bool(cur[COL_Q41]);
        builder.assert_bool(cur[COL_Q52]);
        builder.assert_eq(cur[COL_Q24] + cur[COL_Q41] + cur[COL_Q52], blast * b[3]);
        cur[COL_Q24].into()
    } else {
        AB::Expr::ZERO
    };
    let q41 = if one_block {
        cur[COL_Q41].into()
    } else {
        AB::Expr::ZERO
    };
    let q52 = if one_block {
        cur[COL_Q52].into()
    } else {
        AB::Expr::ZERO
    };
    let q21 = if one_block {
        builder.assert_bool(cur[COL_Q21]);
        builder.assert_bool(cur[COL_B3N]);
        builder.assert_eq(cur[COL_Q21], blast * cur[COL_NB4]);
        builder.assert_eq(cur[COL_B3N], b[3] * (AB::Expr::ONE - blast));
        cur[COL_Q21].into()
    } else {
        AB::Expr::ZERO
    };
    let four_len = if one_block {
        AB::Expr::from(field(24)) * q24
            + AB::Expr::from(field(41)) * q41
            + AB::Expr::from(field(52)) * q52
            + AB::Expr::from(field(21)) * q21
    } else {
        AB::Expr::from(field(24)) * blast * b[3]
    };

    let last_idx = AB::Expr::from(field((n_openings - 1) as u64));
    builder.assert_zero(hlast * (hidx - last_idx.clone()));
    builder.assert_eq(hinv * (hidx - last_idx) + hlast, AB::Expr::ONE);

    builder.assert_eq(endn, ko * oi[7]);
    builder.assert_eq(wrapn, endn * (AB::Expr::ONE - blast));
    builder.assert_eq(rootn, endn * blast);
    builder.assert_eq(wraph, rootn * (AB::Expr::ONE - hlast));
    builder.assert_eq(nroot, rootn * hlast);
    builder.assert_eq(
        cur[COL_BLEN],
        AB::Expr::from(field(64)) * (AB::Expr::ONE - blast)
            + AB::Expr::from(field(33)) * q33
            + AB::Expr::from(field(49)) * q49
            + AB::Expr::from(field(51)) * blast * b[1]
            + AB::Expr::from(field(11)) * blast * b[2]
            + four_len,
    );
    builder.assert_eq(
        cur[COL_BFLG],
        AB::Expr::from(field(CHUNK_START as u64)) * b[0]
            + AB::Expr::from(field((CHUNK_END | ROOT) as u64)) * blast,
    );
    for i in 0..8 {
        builder.assert_eq(
            cur[COL_NCVO + 2 * i],
            oi[i] * cur[COL_XX] + (AB::Expr::ONE - oi[i]) * cur[COL_NCV + 2 * i],
        );
        builder.assert_eq(
            cur[COL_NCVO + 2 * i + 1],
            oi[i] * cur[COL_XX + 1] + (AB::Expr::ONE - oi[i]) * cur[COL_NCV + 2 * i + 1],
        );
    }

    for k in 0..NODE_DIGEST_BLOCKS {
        let mut bk = builder.when(b[k]);
        for j in 0..32 {
            bk.assert_eq(cur[COL_MSG + j], cur[COL_TPRE + 32 * k + j]);
        }
    }
    for k in 0..NODE_DIGEST_BLOCKS - 1 {
        let mut bk = builder.when(b[k]);
        for j in 0..32 {
            bk.assert_eq(cur[COL_NMSG + j], cur[COL_TPRE + 32 * (k + 1) + j]);
        }
    }
    if one_block {
        let mut b4 = builder.when(cur[COL_NB4]);
        for j in 0..32 {
            b4.assert_eq(cur[COL_MSG + j], cur[COL_TPRE5 + j]);
        }
        let mut b3n = builder.when(cur[COL_B3N]);
        for j in 0..32 {
            b3n.assert_eq(cur[COL_NMSG + j], cur[COL_TPRE5 + j]);
        }
        let mut lastb = builder.when(blast);
        for j in 0..32 {
            lastb.assert_zero(cur[COL_NMSG + j]);
        }
    } else {
        let mut lastb = builder.when(b[3]);
        for j in 0..32 {
            lastb.assert_zero(cur[COL_NMSG + j]);
        }
    }

    {
        let mut first = builder.when_first_row();
        first.assert_one(kg);
        first.assert_zero(ko);
        first.assert_zero(pad);
        if one_block {
            // Chrono HeightMatch may start with 1-block prio (blast=1).
            first.assert_eq(blast, cur[COL_Q33] + cur[COL_Q49]);
        } else {
            first.assert_zero(blast);
        }
        first.assert_zero(hidx);
        first.assert_zero(hlast);
        first.assert_one(gi[0]);
        first.assert_one(rnd[0]);
        first.assert_one(b[0]);
        // Init from row BLEN/BFLG so 1-block first opening works.
        let iv4 = [IV[0], IV[1], IV[2], IV[3]];
        for j in 0..8 {
            first.assert_eq(
                cur[COL_S + 2 * j],
                AB::Expr::from(field(lo(IV[j]) as u64)),
            );
            first.assert_eq(
                cur[COL_S + 2 * j + 1],
                AB::Expr::from(field(hi(IV[j]) as u64)),
            );
        }
        for j in 0..4 {
            first.assert_eq(
                cur[COL_S + 16 + 2 * j],
                AB::Expr::from(field(lo(iv4[j]) as u64)),
            );
            first.assert_eq(
                cur[COL_S + 17 + 2 * j],
                AB::Expr::from(field(hi(iv4[j]) as u64)),
            );
        }
        for j in 24..28 {
            first.assert_zero(cur[COL_S + j]);
        }
        first.assert_eq(cur[COL_S + 28], cur[COL_BLEN]);
        first.assert_zero(cur[COL_S + 29]);
        first.assert_eq(cur[COL_S + 30], cur[COL_BFLG]);
        first.assert_zero(cur[COL_S + 31]);
        for i in 0..8 {
            first.assert_eq(
                cur[COL_NCV + 2 * i],
                AB::Expr::from(field(lo(IV[i]) as u64)),
            );
            first.assert_eq(
                cur[COL_NCV + 2 * i + 1],
                AB::Expr::from(field(hi(IV[i]) as u64)),
            );
        }
    }
    {
        let mut last = builder.when_last_row();
        last.assert_one(pad);
        for i in 0..16 {
            last.assert_eq(cur[COL_NCV + i], pis[i]);
        }
    }
    {
        let mut t = builder.when_transition();
        t.assert_eq(nxt[COL_TPAD], pad + nroot);
        t.assert_eq(nxt[COL_KG], kg - lastg + wrapn + wraph);
        t.assert_eq(nxt[COL_KO], lastg + ko * (AB::Expr::ONE - oi[7]));
        t.assert_eq(nxt[COL_GI], stepr + wrapn + wraph);
        for k in 1..8 {
            t.assert_eq(nxt[COL_GI + k], gi[k - 1] * (AB::Expr::ONE - gi[7]));
        }
        t.assert_eq(
            nxt[COL_RND],
            rnd[0] * (AB::Expr::ONE - gi[7]) + wrapn + wraph,
        );
        for r in 1..7 {
            t.assert_eq(
                nxt[COL_RND + r],
                rnd[r] * (AB::Expr::ONE - gi[7]) + rnd[r - 1] * stepr,
            );
        }
        t.assert_eq(nxt[COL_OI], lastg);
        for i in 1..8 {
            t.assert_eq(nxt[COL_OI + i], oi[i - 1] * (AB::Expr::ONE - oi[7]));
        }
        t.assert_eq(nxt[COL_NB], b[0] * (AB::Expr::ONE - endn) + wraph);
        for k in 1..NODE_DIGEST_BLOCKS {
            t.assert_eq(
                nxt[COL_NB + k],
                b[k] * (AB::Expr::ONE - endn) + b[k - 1] * wrapn,
            );
        }
        if one_block {
            t.assert_eq(
                nxt[COL_NB4],
                cur[COL_NB4] * (AB::Expr::ONE - endn) + b[3] * wrapn,
            );
        }
        t.assert_eq(
            nxt[COL_HIDX],
            wraph * (hidx + AB::Expr::ONE) + (AB::Expr::ONE - wraph - nroot - pad) * hidx,
        );
        t.assert_zero((AB::Expr::ONE - endn) * (nxt[COL_BLAST] - blast));
        if !one_block {
            t.assert_zero(wraph * nxt[COL_BLAST]);
        }
        t.assert_zero(nroot * nxt[COL_BLAST]);
        t.assert_zero(pad * nxt[COL_BLAST]);
        if one_block {
            t.assert_zero((AB::Expr::ONE - rootn) * (nxt[COL_Q33] - cur[COL_Q33]));
            t.assert_zero((AB::Expr::ONE - rootn) * (nxt[COL_Q49] - cur[COL_Q49]));
            t.assert_zero((AB::Expr::ONE - endn) * (nxt[COL_Q24] - cur[COL_Q24]));
            t.assert_zero((AB::Expr::ONE - endn) * (nxt[COL_Q41] - cur[COL_Q41]));
            t.assert_zero((AB::Expr::ONE - endn) * (nxt[COL_Q52] - cur[COL_Q52]));
            t.assert_zero((AB::Expr::ONE - endn) * (nxt[COL_Q21] - cur[COL_Q21]));
        }
        let iv4 = [IV[0], IV[1], IV[2], IV[3]];
        let next_len = nxt[COL_BLEN];
        let next_flg = nxt[COL_BFLG];
        let wrap = wrapn + wraph;
        for j in 0..8 {
            let iv_lo = AB::Expr::from(field(lo(IV[j]) as u64));
            let iv_hi = AB::Expr::from(field(hi(IV[j]) as u64));
            t.assert_eq(
                nxt[COL_S + 2 * j],
                wrapn * cur[COL_NCVO + 2 * j]
                    + wraph * iv_lo
                    + pad * cur[COL_S + 2 * j]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 2 * j],
            );
            t.assert_eq(
                nxt[COL_S + 2 * j + 1],
                wrapn * cur[COL_NCVO + 2 * j + 1]
                    + wraph * iv_hi
                    + pad * cur[COL_S + 2 * j + 1]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 2 * j + 1],
            );
        }
        for j in 0..4 {
            let iv_lo = AB::Expr::from(field(lo(iv4[j]) as u64));
            let iv_hi = AB::Expr::from(field(hi(iv4[j]) as u64));
            t.assert_eq(
                nxt[COL_S + 16 + 2 * j],
                wrap.clone() * iv_lo
                    + pad * cur[COL_S + 16 + 2 * j]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 16 + 2 * j],
            );
            t.assert_eq(
                nxt[COL_S + 17 + 2 * j],
                wrap.clone() * iv_hi
                    + pad * cur[COL_S + 17 + 2 * j]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 17 + 2 * j],
            );
        }
        for j in 24..28 {
            t.assert_eq(
                nxt[COL_S + j],
                pad * cur[COL_S + j] + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + j],
            );
        }
        t.assert_eq(
            nxt[COL_S + 28],
            wrap.clone() * next_len
                + pad * cur[COL_S + 28]
                + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 28],
        );
        t.assert_eq(
            nxt[COL_S + 29],
            pad * cur[COL_S + 29] + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 29],
        );
        t.assert_eq(
            nxt[COL_S + 30],
            wrap.clone() * next_flg
                + pad * cur[COL_S + 30]
                + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 30],
        );
        t.assert_eq(
            nxt[COL_S + 31],
            pad * cur[COL_S + 31] + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_SO + 31],
        );
        for i in 0..16 {
            let iv_limb = if i % 2 == 0 {
                AB::Expr::from(field(lo(IV[i / 2]) as u64))
            } else {
                AB::Expr::from(field(hi(IV[i / 2]) as u64))
            };
            t.assert_eq(
                nxt[COL_NCV + i],
                wraph * iv_limb
                    + pad * cur[COL_NCV + i]
                    + (AB::Expr::ONE - wraph - pad) * cur[COL_NCVO + i],
            );
        }
        for i in 0..32 {
            t.assert_eq(
                nxt[COL_MSG + i],
                wrapn * cur[COL_NMSG + i]
                    + wraph * nxt[COL_TPRE + i]
                    + pad * cur[COL_MSG + i]
                    + (AB::Expr::ONE - wrap.clone() - pad) * cur[COL_MSG + i],
            );
        }
        for i in 0..128 {
            t.assert_zero((AB::Expr::ONE - wraph) * (nxt[COL_TPRE + i] - cur[COL_TPRE + i]));
        }
        if one_block {
            for i in 0..32 {
                t.assert_zero((AB::Expr::ONE - wraph) * (nxt[COL_TPRE5 + i] - cur[COL_TPRE5 + i]));
            }
        }
        for i in 0..32 {
            t.assert_zero(
                (AB::Expr::ONE - wrapn - wraph) * (nxt[COL_NMSG + i] - cur[COL_NMSG + i]),
            );
        }
    }
    {
        let mut r = builder.when(nroot);
        for i in 0..7 {
            r.assert_eq(cur[COL_NCV + 2 * i], pis[2 * i]);
            r.assert_eq(cur[COL_NCV + 2 * i + 1], pis[2 * i + 1]);
        }
        r.assert_eq(cur[COL_XX], pis[14]);
        r.assert_eq(cur[COL_XX + 1], pis[15]);
    }
}

fn generate_engine_tape_trace(preimages: &[Vec<u8>]) -> RowMajorMatrix<Val> {
    generate_mixed_openings_trace(preimages, ENGINE_TAPE_OPENINGS, T_ROWS, true)
}

fn generate_mixed_openings_trace(
    preimages: &[Vec<u8>],
    n: usize,
    rows: usize,
    one_block: bool,
) -> RowMajorMatrix<Val> {
    assert_eq!(preimages.len(), n);
    let width = if one_block { H_WIDTH } else { T_WIDTH };
    let mut values = vec![Val::ZERO; rows * width];
    let mut row_off = 0usize;
    let mut last_dig = [0u32; 8];
    for (h, pre) in preimages.iter().enumerate() {
        let nblocks = opening_nblocks(pre.len());
        if one_block {
            assert!(matches!(
                pre.len(),
                PRIO_ORDER_BYTES
                    | PRIO_OWNER_BYTES
                    | SEEN_NODE_BYTES
                    | NONCE_NODE_BYTES
                    | RESTING_NODE_BYTES
                    | INPUT_COMMIT_BYTES
                    | INC_ROOT_BYTES
                    | SETTLEMENT_COMMIT_BYTES
            ));
        } else {
            assert!(matches!(
                pre.len(),
                SEEN_NODE_BYTES | NONCE_NODE_BYTES | RESTING_NODE_BYTES
            ));
        }
        let words80 = if one_block {
            padded_msg_words_80(pre)
        } else {
            let w = padded_msg_words_n(pre);
            let mut e = [0u32; 80];
            e[..64].copy_from_slice(&w);
            e
        };
        let mut words = [0u32; 64];
        words.copy_from_slice(&words80[..64]);
        last_dig = words32(&blake3_hash_msg(pre));
        fill_opening_n_cols(&mut values, width, row_off, pre);
        let (hidx, hlast, hinv) = tape_hidx_flags(h, n);
        let q33 = one_block && pre.len() == PRIO_ORDER_BYTES;
        let q49 = one_block && pre.len() == PRIO_OWNER_BYTES;
        for r in 0..nblocks * C_ROWS {
            let row = &mut values[(row_off + r) * width..(row_off + r + 1) * width];
            row[COL_HIDX] = hidx;
            row[COL_HLAST] = hlast;
            row[COL_HINV] = hinv;
            put_words64(row, COL_TPRE, &words);
            if one_block {
                for i in 0..16 {
                    put_limbs(row, COL_TPRE5 + 2 * i, words80[64 + i]);
                }
            }
            let bi = r / C_ROWS;
            let last_block = bi + 1 == nblocks;
            if last_block {
                row[COL_BLAST] = Val::ONE;
            }
            if one_block && bi == 3 && !last_block {
                row[COL_B3N] = Val::ONE;
            }
            if one_block && last_block && q33 {
                row[COL_Q33] = Val::ONE;
            }
            if one_block && last_block && q49 {
                row[COL_Q49] = Val::ONE;
            }
            if one_block && last_block && pre.len() == RESTING_NODE_BYTES {
                row[COL_Q24] = Val::ONE;
            }
            if one_block && last_block && pre.len() == INPUT_COMMIT_BYTES {
                row[COL_Q41] = Val::ONE;
            }
            if one_block && last_block && pre.len() == INC_ROOT_BYTES {
                row[COL_Q52] = Val::ONE;
            }
            if one_block && last_block && pre.len() == SETTLEMENT_COMMIT_BYTES {
                row[COL_Q21] = Val::ONE;
            }
            let (blen, flags) = opening_block_len_flags(bi, nblocks, pre.len());
            row[COL_BLEN] = field(blen as u64);
            row[COL_BFLG] = field(flags as u64);
            if r + 1 == nblocks * C_ROWS {
                if h + 1 < n {
                    row[COL_TWRAP] = Val::ONE;
                } else {
                    row[COL_TROOT] = Val::ONE;
                }
            }
        }
        row_off += nblocks * C_ROWS;
    }
    let active = row_off;
    assert!(active < rows);
    let last = values[(active - 1) * width..active * width].to_vec();
    let pad_last = field((n - 1) as u64);
    let pad_inv = (Val::ZERO - pad_last).inverse();
    for i in active..rows {
        let row = &mut values[i * width..(i + 1) * width];
        fill_g_columns(
            row,
            Blake3G {
                a: 0,
                b: 0,
                c: 0,
                d: 0,
                x: 0,
                y: 0,
            },
        );
        row[COL_S..COL_S + 32].copy_from_slice(&last[COL_S..COL_S + 32]);
        row[COL_SO..COL_SO + 32].copy_from_slice(&last[COL_SO..COL_SO + 32]);
        row[COL_MSG..COL_MSG + 32].copy_from_slice(&last[COL_MSG..COL_MSG + 32]);
        row[COL_TPRE..COL_TPRE + 128].copy_from_slice(&last[COL_TPRE..COL_TPRE + 128]);
        if one_block {
            row[COL_TPRE5..COL_TPRE5 + 32].copy_from_slice(&last[COL_TPRE5..COL_TPRE5 + 32]);
        }
        row[COL_TPAD] = Val::ONE;
        row[COL_BLEN] = field(64);
        row[COL_HINV] = pad_inv;
        put_words8(row, COL_NCV, &last_dig);
        put_words8(row, COL_NCVO, &last_dig);
    }
    RowMajorMatrix::new(values, width)
}

fn public_engine_tape(preimages: &[Vec<u8>]) -> [Val; T_PIS] {
    let last = blake3_hash_msg(preimages.last().expect("openings"));
    let dw = words32(&last);
    let mut pis = [Val::ZERO; T_PIS];
    for i in 0..8 {
        pis[2 * i] = field(lo(dw[i]) as u64);
        pis[2 * i + 1] = field(hi(dw[i]) as u64);
    }
    pis
}

#[derive(Clone, Debug)]
pub struct EngineTapeProof {
    pub bytes: Vec<u8>,
}

pub fn prove_engine_tape_with(
    preimages: Vec<Vec<u8>>,
    class: FriClass,
) -> Result<EngineTapeProof, ProveError> {
    let config = make_config(class);
    let trace = generate_engine_tape_trace(&preimages);
    let pis = public_engine_tape(&preimages);
    let proof = prove(&config, &EngineTapeAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(EngineTapeProof { bytes })
}

pub fn verify_engine_tape_with(
    preimages: Vec<Vec<u8>>,
    proof: &EngineTapeProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let config = make_config(class);
    let pis = public_engine_tape(&preimages);
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &EngineTapeAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_engine_tape_and_report_with(
    preimages: Vec<Vec<u8>>,
    class: FriClass,
) -> Result<(EngineTapeProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_engine_tape_with(preimages.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_engine_tape_with(preimages, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

#[derive(Clone, Debug)]
pub struct HeightOpeningsProof {
    pub bytes: Vec<u8>,
}

pub fn prove_height_openings_with(
    preimages: Vec<Vec<u8>>,
    class: FriClass,
) -> Result<HeightOpeningsProof, ProveError> {
    let config = make_config(class);
    let trace = generate_mixed_openings_trace(&preimages, HEIGHT_OPENINGS, HO_ROWS, true);
    let pis = public_engine_tape(&preimages);
    let proof = prove(&config, &HeightOpeningsAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(HeightOpeningsProof { bytes })
}

pub fn verify_height_openings_with(
    preimages: Vec<Vec<u8>>,
    proof: &HeightOpeningsProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    if preimages.len() != HEIGHT_OPENINGS {
        return Err(Plonky3VerifyError::Rejected);
    }
    let config = make_config(class);
    let pis = public_engine_tape(&preimages);
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &HeightOpeningsAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_height_openings_and_report_with(
    preimages: Vec<Vec<u8>>,
    class: FriClass,
) -> Result<(HeightOpeningsProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_height_openings_with(preimages.clone(), class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_height_openings_with(preimages, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

/// Envelope: `public_statement_id` || preimages || STARK. PIs are last digest.
pub fn encode_height_pi(
    statement_id: [u8; 32],
    preimages: &[Vec<u8>],
    proof: &HeightOpeningsProof,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + proof.bytes.len());
    out.extend_from_slice(&statement_id);
    out.extend_from_slice(&(preimages.len() as u32).to_le_bytes());
    for p in preimages {
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&proof.bytes);
    out
}

pub fn decode_height_pi(bytes: &[u8]) -> Option<([u8; 32], Vec<Vec<u8>>, HeightOpeningsProof)> {
    if bytes.len() < 36 {
        return None;
    }
    let mut sid = [0u8; 32];
    sid.copy_from_slice(&bytes[..32]);
    let n = u32::from_le_bytes(bytes[32..36].try_into().ok()?) as usize;
    if n != HEIGHT_OPENINGS {
        return None;
    }
    let mut i = 36usize;
    let mut preimages = Vec::with_capacity(n);
    for _ in 0..n {
        if i + 4 > bytes.len() {
            return None;
        }
        let len = u32::from_le_bytes(bytes[i..i + 4].try_into().ok()?) as usize;
        i += 4;
        if i + len > bytes.len() {
            return None;
        }
        preimages.push(bytes[i..i + len].to_vec());
        i += len;
    }
    Some((
        sid,
        preimages,
        HeightOpeningsProof {
            bytes: bytes[i..].to_vec(),
        },
    ))
}

/// Mid-apply books root (16 limbs) after match-step public inputs.
const MID_PIS: usize = 16;
const MID_PI_OFF: usize = T_PIS + MATCH_PIS;
const HM_PIS: usize = MID_PI_OFF + MID_PIS;
const COL_LAT: usize = H_WIDTH + MATCH_WIDTH;
const COL_IS5: usize = COL_LAT;
const COL_I5INV: usize = COL_LAT + 1;
/// Demoted seen (hidx 7); latch for left-child edge into root.
const COL_IS7: usize = COL_LAT + 2;
const COL_I7INV: usize = COL_LAT + 3;
const COL_IS5R: usize = COL_LAT + 4;
const COL_IS7R: usize = COL_LAT + 5;
/// Seen root after rotate (hidx 8).
const COL_IS8: usize = COL_LAT + 6;
const COL_I8INV: usize = COL_LAT + 7;
const COL_IS8R: usize = COL_LAT + 8;
const COL_LATN: usize = COL_LAT + 9;
const COL_LATS: usize = COL_LATN + 16;
const COL_NBIT: usize = COL_LATS + 16;
const COL_SBIT: usize = COL_NBIT + 32 * 8;
const COL_GAP: usize = COL_SBIT + 32 * 8;
const GAP_BITS: usize = 8 * 3;
const COL_Q52P: usize = COL_GAP + GAP_BITS;
const COL_Q52G: usize = COL_Q52P + 1;
/// Seen 115 B last-len 51 (`blast·b[1]`); nonce 139 B last-len 11 (`blast·b[2]`).
const COL_Q51: usize = COL_Q52G + 1;
const COL_Q11: usize = COL_Q51 + 1;
const COL_IS3: usize = COL_Q11 + 1;
const COL_I3INV: usize = COL_IS3 + 1;
const COL_IS6: usize = COL_I3INV + 1;
const COL_I6INV: usize = COL_IS6 + 1;
const COL_IS11: usize = COL_I6INV + 1;
const COL_I11INV: usize = COL_IS11 + 1;
const COL_IS12: usize = COL_I11INV + 1;
const COL_I12INV: usize = COL_IS12 + 1;
/// Seen left empty except hidx 8; nonce left empty except hidx 5.
const COL_SEEN_RE: usize = COL_I12INV + 1;
const COL_NONCE_LE: usize = COL_SEEN_RE + 1;
const COL_IS4: usize = COL_NONCE_LE + 1;
const COL_I4INV: usize = COL_IS4 + 1;
const COL_IS4R: usize = COL_I4INV + 1;
/// `COL_IS6 * COL_ROOTN` (seen take leaf root row).
const COL_IS6R: usize = COL_IS4R + 1;
const COL_LAT4: usize = COL_IS6R + 1;
const COL_LAT6: usize = COL_LAT4 + 16;
const COL_B4: usize = COL_LAT6 + 16;
const COL_B6: usize = COL_B4 + 256;
/// `COL_Q24 * COL_ROOTN` (degree-2 selector for mid-books bind).
const COL_Q24R: usize = COL_B6 + 256;
/// Mid INC among three `q52` openings (hidx 16).
const COL_Q52M: usize = COL_Q24R + 1;
const COL_IS14: usize = COL_Q52M + 1;
const COL_I14INV: usize = COL_IS14 + 1;
const COL_IS15: usize = COL_I14INV + 1;
const COL_I15INV: usize = COL_IS15 + 1;
/// Latch opening 1 `out` (mid seen root).
const COL_IS1: usize = COL_I15INV + 1;
const COL_I1INV: usize = COL_IS1 + 1;
const COL_IS1R: usize = COL_I1INV + 1;
const COL_LAT1: usize = COL_IS1R + 1;
/// Bit unpack of [`COL_LAT1`] (opening 1 `out`). Not compress `COL_B1`.
const COL_LAT1B: usize = COL_LAT1 + 16;
/// OwnerId prio as 4×16-bit LE limbs (digest bytes 0..8) for key byte 1 / 2.
const COL_LAT_PN1: usize = COL_LAT1B + 256;
const COL_LAT_PN2: usize = COL_LAT_PN1 + 4;
/// OrderId prio 4×16-bit limbs for key byte 1 / 2.
const COL_LAT_PO1: usize = COL_LAT_PN2 + 4;
const COL_LAT_PO2: usize = COL_LAT_PO1 + 4;
/// Load pulses for prio latches (`q49`/`q33` × key flag).
const COL_LOAD_PN1: usize = COL_LAT_PO2 + 4;
const COL_LOAD_PN2: usize = COL_LOAD_PN1 + 1;
const COL_LOAD_PO1: usize = COL_LOAD_PN2 + 1;
const COL_LOAD_PO2: usize = COL_LOAD_PO1 + 1;
/// Sticky: all four prio latches loaded (after order key-2 prio).
const COL_HEAP_RDY: usize = COL_LOAD_PO2 + 1;
const COL_HEAP_STICKY: usize = COL_HEAP_RDY + 1;
/// Borrow chain for `pn2 - pn1 - 1` and `po2 - po1 - 1` (4 limbs + 4 borrows + 64 bits each).
const COL_HEAP_ND: usize = COL_HEAP_STICKY + 1;
const COL_HEAP_NB: usize = COL_HEAP_ND + 4;
const COL_HEAP_NDB: usize = COL_HEAP_NB + 4;
const COL_HEAP_SD: usize = COL_HEAP_NDB + 64;
const COL_HEAP_SB: usize = COL_HEAP_SD + 4;
const COL_HEAP_SDB: usize = COL_HEAP_SB + 4;
/// First key byte latched from openings 4 / 7 for BST on edges 5←4 / 8←7.
const COL_LAT_K4: usize = COL_HEAP_SDB + 64;
const COL_LAT_K6: usize = COL_LAT_K4 + 1;
/// `key5 - key4 - 1` and `key8 - key7 - 1` as 8-bit witnesses.
const COL_BST_ND: usize = COL_LAT_K6 + 1;
const COL_BST_SD: usize = COL_BST_ND + 8;
/// Latch opening 0 `out` (nonce demote twin of opening 4).
const COL_IS0: usize = COL_BST_SD + 8;
const COL_I0INV: usize = COL_IS0 + 1;
const COL_IS0R: usize = COL_I0INV + 1;
const COL_LAT0: usize = COL_IS0R + 1;
/// Insert algebra: Place2 OrderId from order prio (hidx 10) → seen + `I` take
/// id; Place2 OwnerId from owner prio (hidx 6) → nonce + `I` take owner.
/// Place1: order prio (hidx 2) → seen/rest/`I` sell id; owner prio (hidx 0) →
/// nonce/`I` sell owner; resting order prio (hidx 4) → LAT_SID; rest leaf
/// owner → LAT_SOWN.
const COL_LOAD_TID: usize = COL_LAT0 + 16;
const COL_LAT_TID0: usize = COL_LOAD_TID + 1;
const COL_LOAD_TOWN: usize = COL_LAT_TID0 + 1;
const COL_LAT_TOWN0: usize = COL_LOAD_TOWN + 1;
/// `COL_IS3 * COL_ROOTN` (nonce k2 leaf root row).
const COL_IS3R: usize = COL_LAT_TOWN0 + 1;
const COL_IS2: usize = COL_IS3R + 1;
const COL_I2INV: usize = COL_IS2 + 1;
const COL_LOAD_SID: usize = COL_I2INV + 1;
const COL_LAT_SID0: usize = COL_LOAD_SID + 1;
const COL_LOAD_SOWN: usize = COL_LAT_SID0 + 1;
const COL_LAT_SOWN0: usize = COL_LOAD_SOWN + 1;
/// Resting-map order prio (hidx 4): `q33 ∧ ¬is2 ∧ ¬is12 ∧ rootn`.
const COL_LOAD_RP: usize = COL_LAT_SOWN0 + 1;
const LAT_WIDTH: usize = COL_LOAD_RP + 1 - COL_LAT;
const HM_WIDTH: usize = H_WIDTH + MATCH_WIDTH + LAT_WIDTH;
/// Chronological apply order (not node||prio). Edges: nonce `9←8`, seen `13←12`.
const HIDX_NONCE_ROOT: u64 = 9;
const HIDX_SEEN_ROOT: u64 = 13;
const HIDX_NONCE_PREV: u64 = 8;
const HIDX_NONCE_FIRST: u64 = 1;
const HIDX_NONCE_K2: u64 = 7;
/// Seen take leaf (OrderId 5) before rotate rehash.
const HIDX_SEEN_K5: u64 = 11;
/// Demoted former seen root (OrderId 1); left child of new root.
const HIDX_SEEN_DEMOT: u64 = 12;
const HIDX_OWNER_K2: u64 = 6;
const HIDX_ORDER_K1: u64 = 2;
const HIDX_ORDER_K5: u64 = 10;
/// Offsets of map digests inside [`INC_ROOT_BYTES`] (this fixture).
pub const NONCE_ROOT_OFF: usize = 121;
pub const SEEN_ROOT_OFF: usize = 167;
pub const REST_ROOT_OFF: usize = 212;
const INC_HEADER_WORDS: usize = 27;
const INC_TPRE_WORDS: usize = INC_ROOT_BYTES / 4;
const THIS_HEIGHT: u64 = 1;
const THIS_NEXT_TIME: u64 = 1;
const GENESIS_NEXT_TIME: u64 = 0;
/// Remaining `Qty` u64 and `Price` u64 inside a 216 B resting `node_digest`.
const RESTING_QTY_OFF: usize = 112;
const RESTING_PRICE_OFF: usize = 120;
/// Take Place qty/price inside the 233 B `I` commit preimage (unaligned).
const INPUT_TAKE_QTY_OFF: usize = 169;
const INPUT_TAKE_PRICE_OFF: usize = 177;
/// Buy side byte 168 is 0; qty < 256 lives at byte 169 → TPRE word 42 = qty << 8.
const TAKE_QTY_WORD: usize = 42;
const TAKE_PRICE_WORD: usize = 44;
const TAKE_PACK: u64 = 256;
/// Four 61 B `SettlementDelta`s after domain/version/len/count.
const SETTLE_DELTA0_OFF: usize = 33;
const SETTLE_DELTA_LEN: usize = 61;
const RECEIPT_DOMAIN_LEN: usize = 19;
const RECEIPT_PAYLOAD_LEN: u64 = 248;
const RECEIPT_COUNT: u64 = 4;
const RECEIPT_DELTA_TAG: [u8; 8] = *b"DELTA\0\0\0";
const SETTLE_DEBIT1: u64 = 1;
const SETTLE_OWNER_IN_DELTA: usize = 8;
const SETTLE_ASSET_IN_DELTA: usize = 40;
const SETTLE_AMT_IN_DELTA: usize = 44;
const SETTLE_DEBIT_IN_DELTA: usize = 60;
/// Taker buy: credit base 10, debit quote 900, maker opposite.
const SETTLE_FILL_AMT: u64 = 10;
const SETTLE_QUOTE_AMT: u64 = 900;
const RESTING_OWNER_OFF: usize = 128;
const INPUT_TAKE_OWNER_OFF: usize = 185;
const INPUT_SELL_OWNER_OFF: usize = 84;
/// First Place (sell) qty/price in `I`. 4-aligned: qty 68, price 76, owner 84.
const INPUT_SELL_QTY_OFF: usize = 68;
const INPUT_SELL_PRICE_OFF: usize = 76;
const SELL_QTY_WORD: usize = 17;
const SELL_PRICE_WORD: usize = 19;
const RESTING_ID_OFF: usize = 91;
const RESTING_INST_OFF: usize = 107;
const RESTING_SIDE_OFF: usize = 111;
const INPUT_SELL_ID_OFF: usize = 47;
const INPUT_SELL_INST_OFF: usize = 63;
const INPUT_SELL_SIDE_OFF: usize = 67;
const MAKER_ORDER_ID_BYTE: u64 = 1;
const TAKER_ORDER_ID_BYTE: u64 = 5;
const INSTRUMENT_ID_BYTE: u64 = 1;
const SELL_SIDE_BYTE: u64 = 1;
const INPUT_TAKE_ID_OFF: usize = 148;
const INPUT_TAKE_INST_OFF: usize = 164;
const TAKE_ID_WORD: usize = 37;
const TAKE_INST_WORD: usize = 41;
const RESTING_EXPIRY_OFF: usize = 160;
const RESTING_NONCE_OFF: usize = 168;
const RESTING_TIME_OFF: usize = 176;
const RESTING_LEFT_OFF: usize = 19;
const RESTING_RIGHT_OFF: usize = 184;
const SEEN_RIGHT_OFF: usize = 83;
const NONCE_RIGHT_OFF: usize = 107;
const RESTING_KEY_LEN_OFF: usize = 51;
const RESTING_KEY_OFF: usize = 59;
const RESTING_KEY_LEN: u64 = 16;
const RESTING_VALUE_LEN_OFF: usize = 75;
const RESTING_VALUE_LEN: u64 = 101;
const RESTING_TAG_OFF: usize = 83;
const RESTING_TAG: [u8; 8] = *b"RESTING\0";
const NODE_DOMAIN_LEN: usize = 17;
const SEEN_VALUE_LEN: u64 = 0;
const NONCE_KEY_LEN: u64 = 32;
const NONCE_VALUE_LEN: u64 = 8;
const NONCE_VALUE_OFF: usize = 99;
const INPUT_SELL_EXPIRY_OFF: usize = 116;
const INPUT_SELL_NONCE_OFF: usize = 124;
const EXPIRY_HEIGHT: u64 = 1000;
const ORDER_NONCE: u64 = 1;
const INPUT_PAYLOAD_LEN: u64 = 206;
const INPUT_COUNT: u64 = 2;
const INPUT_PLACE_TAG: [u8; 8] = *b"INPLACE\0";
const INPUT_ORDER_TAG: [u8; 8] = *b"ORDER\0\0\0";
const INPUT_PLACE0_OFF: usize = 31;
const INPUT_ORDER0_OFF: usize = 39;
const INPUT_PLACE1_OFF: usize = 132;
const INPUT_ORDER1_OFF: usize = 140;
const INPUT_TAKE_EXPIRY_OFF: usize = 217;
const INPUT_TAKE_NONCE_OFF: usize = 225;
/// `INC_DOMAIN` is 15 B (`plx/clob/inc/v1`), then version, then `height`.
const INC_DOMAIN_LEN: usize = 15;
const INC_HEIGHT_TAG: [u8; 6] = *b"height";
const INC_HEIGHT_TAG_OFF: usize = 17;
const INC_HEIGHT_LEN: u64 = 8;
const INC_NONCES_TAG: [u8; 6] = *b"nonces";
const INC_SEENID_TAG: [u8; 6] = *b"seenid";
const INC_BOOKS_TAG: [u8; 5] = *b"books";
const INC_NONCES_TAG_OFF: usize = 107;
const INC_SEENID_TAG_OFF: usize = 153;
const INC_BOOKS_TAG_OFF: usize = 199;
const INC_DIGEST_LEN: u64 = 32;
const MAKER_OWNER_BYTE: u64 = 1;
const TAKER_OWNER_BYTE: u64 = 2;
const BASE_ASSET: u64 = 1;
const QUOTE_ASSET: u64 = 2;

/// `Digest::from_bytes` preimage of `commit_list(I, INPUT_DOMAIN)`.
pub fn input_commit_preimage(inputs: &[protocol_types::Input]) -> Vec<u8> {
    commitments::digest_preimage(
        &commitments::commit_list_payload(inputs),
        commitments::INPUT_DOMAIN,
    )
}

/// `Digest::from_bytes` preimage of `commit_list(deltas, RECEIPT_DOMAIN)`.
pub fn settlement_commit_preimage(deltas: &[protocol_types::SettlementDelta]) -> Vec<u8> {
    commitments::digest_preimage(
        &commitments::commit_list_payload(deltas),
        commitments::RECEIPT_DOMAIN,
    )
}

fn fixture_instrument() -> protocol_types::Instrument {
    protocol_types::Instrument {
        id: protocol_types::InstrumentId(1),
        base: protocol_types::AssetId(1),
        quote: protocol_types::AssetId(2),
        lot_size: protocol_types::Qty(1),
        tick_size: protocol_types::Price(1),
    }
}

fn fixture_inc_preimage(next_time: u64) -> Vec<u8> {
    use protocol_types::{CanonicalEncode, ENCODING_VERSION};
    let spec = fixture_instrument();
    let mut instrs = commitments::StateHasher::with_domain(commitments::INC_DOMAIN);
    instrs.tag(b"instrs");
    instrs.write_encoded(&spec);
    let instruments = instrs.finalize();
    let empty = commitments::treap_empty_digest();
    fn push_encoded(pre: &mut Vec<u8>, value: &impl CanonicalEncode) {
        let bytes = value.encode_vec();
        pre.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        pre.extend_from_slice(&bytes);
    }
    let mut pre = Vec::new();
    pre.extend_from_slice(commitments::INC_DOMAIN);
    pre.extend_from_slice(&ENCODING_VERSION.to_le_bytes());
    pre.extend_from_slice(b"height");
    push_encoded(&mut pre, &protocol_types::Height(THIS_HEIGHT));
    pre.extend_from_slice(b"next_t");
    push_encoded(&mut pre, &protocol_types::TimeSeq(next_time));
    pre.extend_from_slice(b"instrs");
    push_encoded(&mut pre, &instruments);
    pre.extend_from_slice(b"nonces");
    push_encoded(&mut pre, &empty);
    pre.extend_from_slice(b"seenid");
    push_encoded(&mut pre, &empty);
    pre.extend_from_slice(b"books");
    push_encoded(&mut pre, &empty);
    debug_assert_eq!(pre.len(), INC_ROOT_BYTES);
    pre
}

/// Genesis `C` INC transcript (empty maps, `next_time=0`). Not `C'` after `F`.
pub fn genesis_inc_preimage() -> Vec<u8> {
    fixture_inc_preimage(GENESIS_NEXT_TIME)
}

/// 14 chrono map hashes plus this height's `I`, genesis INC (`C`), mid INC,
/// settlement, and post INC (`C'`), stacked with match-step. Rotate crossing:
/// take `OrderId` 5. Rest = 216 B leaf (`q24`). Take = `I` (`q41`). Last digest
/// is `post_root`. Nonce/seen map roots equal openings 9/13; resting map root
/// is empty. Take Place id is `from_u128(5)`. Seen keys ∈ {1,5}; nonce/owner ∈
/// {1,2}. Nonce root left (hidx 9) = opening 8 `out`; seen rotate root left
/// (hidx 13) = demoted opening 12 `out` (≡ opening 3). Edges: `9←8`, `13←12`.
/// Mid INC (hidx 16 / `q52m`). Heap+BST on those edges. Demote pins
/// `out(12)=out(3)` and `out(1)=out(8)`. Left-overwrite `7→9` / `11→13` by
/// header composition. Insert: Place1/2 order prios → seen/rest/`I` ids;
/// owner prios → nonce/`I` owners. Openings **19**. Not full
/// rotate/insert/delete. Not `F`.
pub struct HeightMatchAir;

impl<F> BaseAir<F> for HeightMatchAir {
    fn width(&self) -> usize {
        HM_WIDTH
    }

    fn num_public_values(&self) -> usize {
        HM_PIS
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut cols = mixed_openings_next_cols();
        cols.push(COL_Q33);
        cols.push(COL_Q49);
        cols.push(COL_Q24);
        cols.push(COL_Q41);
        cols.push(COL_Q52);
        cols.push(COL_Q21);
        cols.push(COL_NB4);
        cols.push(COL_B3N);
        cols.extend(COL_TPRE5..COL_TPRE5 + 32);
        cols.push(COL_IS5);
        cols.push(COL_IS7);
        cols.push(COL_IS8);
        cols.push(COL_IS5R);
        cols.push(COL_IS7R);
        cols.push(COL_IS8R);
        for i in 0..16 {
            cols.push(COL_LATN + i);
            cols.push(COL_LATS + i);
            cols.push(COL_LAT4 + i);
            cols.push(COL_LAT6 + i);
        }
        cols.push(COL_IS4);
        cols.push(COL_IS4R);
        cols.push(COL_IS6R);
        cols.push(COL_Q24R);
        cols.push(COL_Q52M);
        cols.push(COL_IS1R);
        for i in 0..16 {
            cols.push(COL_LAT1 + i);
        }
        for i in 0..4 {
            cols.push(COL_LAT_PN1 + i);
            cols.push(COL_LAT_PN2 + i);
            cols.push(COL_LAT_PO1 + i);
            cols.push(COL_LAT_PO2 + i);
        }
        cols.push(COL_LOAD_PN1);
        cols.push(COL_LOAD_PN2);
        cols.push(COL_LOAD_PO1);
        cols.push(COL_LOAD_PO2);
        cols.push(COL_HEAP_RDY);
        cols.push(COL_HEAP_STICKY);
        cols.push(COL_LAT_K4);
        cols.push(COL_LAT_K6);
        cols.push(COL_IS0);
        cols.push(COL_IS0R);
        for i in 0..16 {
            cols.push(COL_LAT0 + i);
        }
        cols.push(COL_LOAD_TID);
        cols.push(COL_LAT_TID0);
        cols.push(COL_LOAD_TOWN);
        cols.push(COL_LAT_TOWN0);
        cols.push(COL_IS3R);
        cols.push(COL_IS2);
        cols.push(COL_LOAD_SID);
        cols.push(COL_LAT_SID0);
        cols.push(COL_LOAD_SOWN);
        cols.push(COL_LAT_SOWN0);
        cols.push(COL_LOAD_RP);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Heap borrow eqs under `when(rdy)` are degree 3.
        Some(3)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for HeightMatchAir {
    fn eval(&self, builder: &mut AB) {
        let (pis, cur, nxt) = {
            let main = builder.main();
            let pv = builder.public_values();
            let pis: Vec<AB::PublicVar> = (0..HM_PIS).map(|i| pv[i]).collect();
            let cur: Vec<AB::Var> = (0..HM_WIDTH).map(|i| main.current(i).unwrap()).collect();
            let nxt: Vec<AB::Var> = (0..HM_WIDTH).map(|i| main.next(i).unwrap()).collect();
            (pis, cur, nxt)
        };
        eval_engine_tape(
            builder,
            &cur[..H_WIDTH],
            &nxt[..H_WIDTH],
            &pis[..T_PIS],
            HEIGHT_MATCH_OPENINGS,
            true,
        );
        eval_match(
            builder,
            &cur[H_WIDTH..H_WIDTH + MATCH_WIDTH],
            &pis[T_PIS..MID_PI_OFF],
        );
        eval_bind_rest_leaf(builder, &cur);
        eval_bind_mid_books(builder, &cur, &pis);
        eval_bind_take_i(builder, &cur);
        eval_bind_i_header(builder, &cur);
        eval_bind_inc_domain(builder, &cur);
        eval_bind_settlement(builder, &cur);
        eval_bind_receipt_header(builder, &cur);
        eval_bind_q52_split(builder, &cur);
        eval_bind_q51_q11(builder, &cur);
        eval_bind_seen_header(builder, &cur);
        eval_bind_nonce_header(builder, &cur);
        eval_bind_seen_nonce_children(builder, &cur);
        eval_bind_prio_header(builder, &cur);
        eval_bind_unique_keys(builder, &cur);
        eval_bind_prio_heap(builder, &cur, &nxt);
        eval_bind_inc_header(builder, &cur);
        eval_bind_genesis_c(builder, &cur);
        eval_bind_map_roots(builder, &cur, &nxt);
        eval_bind_mid_inc(builder, &cur, &nxt, &pis);
        eval_bind_inc_map_tags(builder, &cur);
        eval_bind_sibling_children(builder, &cur, &nxt);
        eval_bind_demote_pin(builder, &cur, &nxt);
        eval_bind_bst_edges(builder, &cur, &nxt);
        eval_bind_insert_from_i(builder, &cur, &nxt);
    }
}

fn tpre_lo(word: usize) -> usize {
    COL_TPRE + 2 * word
}

fn tpre5_lo(word: usize) -> usize {
    COL_TPRE5 + 2 * word
}

fn settle_amt_off(i: usize) -> usize {
    SETTLE_DELTA0_OFF + i * SETTLE_DELTA_LEN + SETTLE_AMT_IN_DELTA
}

fn settle_debit_off(i: usize) -> usize {
    SETTLE_DELTA0_OFF + i * SETTLE_DELTA_LEN + SETTLE_DEBIT_IN_DELTA
}

const fn settle_owner_off(i: usize) -> usize {
    SETTLE_DELTA0_OFF + i * SETTLE_DELTA_LEN + SETTLE_OWNER_IN_DELTA
}

const fn settle_asset_off(i: usize) -> usize {
    SETTLE_DELTA0_OFF + i * SETTLE_DELTA_LEN + SETTLE_ASSET_IN_DELTA
}

const _: usize = settle_owner_off(0)
    + settle_asset_off(3)
    + INPUT_SELL_OWNER_OFF
    + INPUT_SELL_QTY_OFF
    + INPUT_SELL_PRICE_OFF
    + INPUT_SELL_ID_OFF
    + INPUT_SELL_INST_OFF
    + INPUT_SELL_SIDE_OFF
    + RESTING_ID_OFF
    + RESTING_INST_OFF
    + RESTING_SIDE_OFF
    + INPUT_TAKE_ID_OFF
    + INPUT_TAKE_INST_OFF
    + RESTING_EXPIRY_OFF
    + RESTING_NONCE_OFF
    + INPUT_SELL_EXPIRY_OFF
    + INPUT_SELL_NONCE_OFF
    + INPUT_TAKE_EXPIRY_OFF
    + INPUT_TAKE_NONCE_OFF
    + RESTING_TIME_OFF
    + RESTING_LEFT_OFF
    + RESTING_RIGHT_OFF
    + RESTING_KEY_LEN_OFF
    + RESTING_KEY_OFF
    + RESTING_VALUE_LEN_OFF
    + RESTING_TAG_OFF
    + RESTING_VALUE_LEN as usize
    + NODE_DOMAIN_LEN
    + RESTING_TAG[0] as usize
    + SEEN_VALUE_LEN as usize
    + NONCE_KEY_LEN as usize
    + NONCE_VALUE_LEN as usize
    + NONCE_VALUE_OFF
    + COL_Q51
    + COL_Q11
    + COL_IS3
    + COL_IS6
    + COL_IS11
    + COL_IS12
    + HIDX_NONCE_K2 as usize
    + HIDX_SEEN_K5 as usize
    + HIDX_OWNER_K2 as usize
    + HIDX_ORDER_K5 as usize
    + INPUT_PAYLOAD_LEN as usize
    + INPUT_COUNT as usize
    + INPUT_PLACE0_OFF
    + INPUT_ORDER0_OFF
    + INPUT_PLACE1_OFF
    + INPUT_ORDER1_OFF
    + INPUT_PLACE_TAG[0] as usize
    + INPUT_ORDER_TAG[0] as usize
    + INC_DOMAIN_LEN
    + INC_HEIGHT_TAG_OFF
    + INC_HEIGHT_LEN as usize
    + INC_HEIGHT_TAG[0] as usize
    + RECEIPT_DOMAIN_LEN
    + RECEIPT_PAYLOAD_LEN as usize
    + RECEIPT_COUNT as usize
    + RECEIPT_DELTA_TAG[0] as usize
    + SETTLE_DEBIT1 as usize
    + INC_NONCES_TAG_OFF
    + INC_SEENID_TAG_OFF
    + INC_BOOKS_TAG_OFF
    + INC_DIGEST_LEN as usize
    + INC_NONCES_TAG[0] as usize
    + INC_SEENID_TAG[0] as usize
    + INC_BOOKS_TAG[0] as usize
    + SEEN_RIGHT_OFF
    + NONCE_RIGHT_OFF
    + COL_SEEN_RE
    + COL_NONCE_LE
    + COL_IS4
    + COL_IS4R
    + COL_IS6R
    + COL_LAT4
    + COL_LAT6
    + HIDX_NONCE_PREV as usize;

/// Resting leaf digest (`q24 ∧ rootn`) equals mid-apply books public inputs.
/// Not Place1 treap algebra; not `F`. Still 19 openings.
fn eval_bind_mid_books<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    pis: &[AB::PublicVar],
) {
    let q24 = cur[COL_Q24];
    let rootn = cur[COL_ROOTN];
    let q24r = cur[COL_Q24R];
    builder.assert_bool(q24r);
    builder.assert_eq(q24r, q24 * rootn);
    {
        let mut w = builder.when(q24r);
        for i in 0..16 {
            w.assert_eq(cur[COL_NCVO + i], pis[MID_PI_OFF + i]);
        }
    }
}

/// On this height the 216 B 4-block is the sell rest (`q24`, last-len 24).
/// Bind match rest qty/price to that leaf.
fn eval_bind_rest_leaf<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    debug_assert_eq!(RESTING_QTY_OFF, 28 * 4);
    debug_assert_eq!(RESTING_PRICE_OFF, 30 * 4);
    let q24 = cur[COL_Q24];
    let rest_q = cur[H_WIDTH];
    let rest_p = cur[H_WIDTH + 1];
    let mut w = builder.when(q24);
    w.assert_eq(cur[tpre_lo(28)], rest_q);
    w.assert_zero(cur[tpre_lo(28) + 1]);
    w.assert_zero(cur[tpre_lo(29)]);
    w.assert_zero(cur[tpre_lo(29) + 1]);
    w.assert_eq(cur[tpre_lo(30)], rest_p);
    w.assert_zero(cur[tpre_lo(30) + 1]);
    w.assert_zero(cur[tpre_lo(31)]);
    w.assert_zero(cur[tpre_lo(31) + 1]);
    debug_assert_eq!(RESTING_OWNER_OFF, 32 * 4);
    w.assert_eq(cur[tpre_lo(32)], AB::Expr::from(field(MAKER_OWNER_BYTE)));
    w.assert_zero(cur[tpre_lo(32) + 1]);
    for word in 33..40 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    debug_assert_eq!(RESTING_ID_OFF, 22 * 4 + 3);
    debug_assert_eq!(RESTING_INST_OFF, 26 * 4 + 3);
    debug_assert_eq!(RESTING_SIDE_OFF, 27 * 4 + 3);
    let pack = AB::Expr::from(field(TAKE_PACK));
    w.assert_eq(cur[tpre_lo(22) + 1], AB::Expr::from(field(MAKER_ORDER_ID_BYTE)) * pack.clone());
    for word in 23..26 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(26)]);
    w.assert_eq(cur[tpre_lo(26) + 1], AB::Expr::from(field(INSTRUMENT_ID_BYTE)) * pack.clone());
    w.assert_zero(cur[tpre_lo(27)]);
    w.assert_eq(cur[tpre_lo(27) + 1], AB::Expr::from(field(SELL_SIDE_BYTE)) * pack);
    debug_assert_eq!(RESTING_EXPIRY_OFF, 40 * 4);
    debug_assert_eq!(RESTING_NONCE_OFF, 42 * 4);
    w.assert_eq(cur[tpre_lo(40)], AB::Expr::from(field(EXPIRY_HEIGHT)));
    w.assert_zero(cur[tpre_lo(40) + 1]);
    w.assert_zero(cur[tpre_lo(41)]);
    w.assert_zero(cur[tpre_lo(41) + 1]);
    w.assert_eq(cur[tpre_lo(42)], AB::Expr::from(field(ORDER_NONCE)));
    w.assert_zero(cur[tpre_lo(42) + 1]);
    w.assert_zero(cur[tpre_lo(43)]);
    w.assert_zero(cur[tpre_lo(43) + 1]);
    debug_assert_eq!(RESTING_TIME_OFF, 44 * 4);
    debug_assert_eq!(GENESIS_NEXT_TIME, 0);
    w.assert_eq(cur[tpre_lo(44)], AB::Expr::from(field(GENESIS_NEXT_TIME)));
    w.assert_zero(cur[tpre_lo(44) + 1]);
    w.assert_zero(cur[tpre_lo(45)]);
    w.assert_zero(cur[tpre_lo(45) + 1]);
    debug_assert_eq!(RESTING_RIGHT_OFF, 46 * 4);
    debug_assert_eq!(RESTING_LEFT_OFF, 4 * 4 + 3);
    let empty = commitments::treap_empty_digest().0;
    let empty_w = words32(&empty);
    for i in 0..8 {
        w.assert_eq(
            cur[tpre_lo(46 + i)],
            AB::Expr::from(field(lo(empty_w[i]) as u64)),
        );
        w.assert_eq(
            cur[tpre_lo(46 + i) + 1],
            AB::Expr::from(field(hi(empty_w[i]) as u64)),
        );
    }
    w.assert_eq(
        cur[tpre_lo(4) + 1],
        AB::Expr::from(field(empty[0] as u64 * TAKE_PACK)),
    );
    for i in 0..7 {
        let off = 1 + 4 * i;
        let word = 5 + i;
        w.assert_eq(
            cur[tpre_lo(word)],
            AB::Expr::from(field(empty[off] as u64 | (empty[off + 1] as u64) << 8)),
        );
        w.assert_eq(
            cur[tpre_lo(word) + 1],
            AB::Expr::from(field(empty[off + 2] as u64 | (empty[off + 3] as u64) << 8)),
        );
    }
    w.assert_eq(
        cur[tpre_lo(12)],
        AB::Expr::from(field(empty[29] as u64 | (empty[30] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(12) + 1],
        AB::Expr::from(field(empty[31] as u64 | RESTING_KEY_LEN << 8)),
    );
    debug_assert_eq!(commitments::TREAP_NODE_DOMAIN.len(), NODE_DOMAIN_LEN);
    debug_assert_eq!(protocol_types::ENCODING_VERSION, 1);
    debug_assert_eq!(RESTING_KEY_LEN_OFF, 12 * 4 + 3);
    debug_assert_eq!(RESTING_KEY_OFF, 14 * 4 + 3);
    debug_assert_eq!(RESTING_VALUE_LEN_OFF, 18 * 4 + 3);
    debug_assert_eq!(RESTING_TAG_OFF, 20 * 4 + 3);
    let domain = commitments::TREAP_NODE_DOMAIN;
    for i in 0..4 {
        let off = 4 * i;
        w.assert_eq(
            cur[tpre_lo(i)],
            AB::Expr::from(field(domain[off] as u64 | (domain[off + 1] as u64) << 8)),
        );
        w.assert_eq(
            cur[tpre_lo(i) + 1],
            AB::Expr::from(field(domain[off + 2] as u64 | (domain[off + 3] as u64) << 8)),
        );
    }
    w.assert_eq(
        cur[tpre_lo(4)],
        AB::Expr::from(field(
            domain[16] as u64 | (protocol_types::ENCODING_VERSION as u64) << 8,
        )),
    );
    w.assert_zero(cur[tpre_lo(13)]);
    w.assert_zero(cur[tpre_lo(13) + 1]);
    w.assert_zero(cur[tpre_lo(14)]);
    w.assert_eq(
        cur[tpre_lo(14) + 1],
        AB::Expr::from(field(MAKER_ORDER_ID_BYTE * TAKE_PACK)),
    );
    for word in 15..18 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(18)]);
    w.assert_eq(
        cur[tpre_lo(18) + 1],
        AB::Expr::from(field(RESTING_VALUE_LEN * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(19)]);
    w.assert_zero(cur[tpre_lo(19) + 1]);
    w.assert_zero(cur[tpre_lo(20)]);
    w.assert_eq(
        cur[tpre_lo(20) + 1],
        AB::Expr::from(field(RESTING_TAG[0] as u64 * TAKE_PACK)),
    );
    w.assert_eq(
        cur[tpre_lo(21)],
        AB::Expr::from(field(RESTING_TAG[1] as u64 | (RESTING_TAG[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(21) + 1],
        AB::Expr::from(field(RESTING_TAG[3] as u64 | (RESTING_TAG[4] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(22)],
        AB::Expr::from(field(RESTING_TAG[5] as u64 | (RESTING_TAG[6] as u64) << 8)),
    );
}

/// Take Place is the second `Input::Place` in this height's `I`. Qty/price
/// are unaligned (bytes 169/177). This instance both are < 256 and Buy side
/// is 0, so TPRE words 42/44 pack as `v << 8`. Sell Place qty/price are
/// 4-aligned (bytes 68/76) and equal match rest. Sell owner is byte 84
/// (`from_byte(1)`). Not a 15-bit extract.
fn eval_bind_take_i<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    debug_assert_eq!(INPUT_TAKE_QTY_OFF, TAKE_QTY_WORD * 4 + 1);
    debug_assert_eq!(INPUT_TAKE_PRICE_OFF, TAKE_PRICE_WORD * 4 + 1);
    let q41 = cur[COL_Q41];
    let take_q = cur[H_WIDTH + 2];
    let take_p = cur[H_WIDTH + 3];
    let pack = AB::Expr::from(field(TAKE_PACK));
    let mut w = builder.when(q41);
    w.assert_eq(cur[tpre_lo(TAKE_QTY_WORD)], take_q * pack.clone());
    w.assert_zero(cur[tpre_lo(TAKE_QTY_WORD) + 1]);
    w.assert_zero(cur[tpre_lo(TAKE_QTY_WORD + 1)]);
    w.assert_zero(cur[tpre_lo(TAKE_QTY_WORD + 1) + 1]);
    w.assert_eq(cur[tpre_lo(TAKE_PRICE_WORD)], take_p * pack);
    w.assert_zero(cur[tpre_lo(TAKE_PRICE_WORD) + 1]);
    w.assert_zero(cur[tpre_lo(TAKE_PRICE_WORD + 1)]);
    w.assert_zero(cur[tpre_lo(TAKE_PRICE_WORD + 1) + 1]);
    debug_assert_eq!(INPUT_TAKE_OWNER_OFF, 46 * 4 + 1);
    w.assert_eq(
        cur[tpre_lo(46)],
        AB::Expr::from(field(TAKER_OWNER_BYTE * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(46) + 1]);
    for word in 47..54 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_eq(cur[tpre_lo(54)], AB::Expr::from(field(0xe800)));
    w.assert_eq(cur[tpre_lo(54) + 1], AB::Expr::from(field(3)));
    debug_assert_eq!(INPUT_TAKE_EXPIRY_OFF, 54 * 4 + 1);
    debug_assert_eq!(INPUT_TAKE_NONCE_OFF, 56 * 4 + 1);
    w.assert_zero(cur[tpre_lo(55)]);
    w.assert_zero(cur[tpre_lo(55) + 1]);
    w.assert_eq(
        cur[tpre_lo(56)],
        AB::Expr::from(field(ORDER_NONCE * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(56) + 1]);
    for word in 57..59 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    debug_assert_eq!(INPUT_SELL_OWNER_OFF, 21 * 4);
    w.assert_eq(cur[tpre_lo(21)], AB::Expr::from(field(MAKER_OWNER_BYTE)));
    w.assert_zero(cur[tpre_lo(21) + 1]);
    for word in 22..29 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    debug_assert_eq!(INPUT_SELL_QTY_OFF, SELL_QTY_WORD * 4);
    debug_assert_eq!(INPUT_SELL_PRICE_OFF, SELL_PRICE_WORD * 4);
    let rest_q = cur[H_WIDTH];
    let rest_p = cur[H_WIDTH + 1];
    w.assert_eq(cur[tpre_lo(SELL_QTY_WORD)], rest_q);
    w.assert_zero(cur[tpre_lo(SELL_QTY_WORD) + 1]);
    w.assert_zero(cur[tpre_lo(SELL_QTY_WORD + 1)]);
    w.assert_zero(cur[tpre_lo(SELL_QTY_WORD + 1) + 1]);
    w.assert_eq(cur[tpre_lo(SELL_PRICE_WORD)], rest_p);
    w.assert_zero(cur[tpre_lo(SELL_PRICE_WORD) + 1]);
    w.assert_zero(cur[tpre_lo(SELL_PRICE_WORD + 1)]);
    w.assert_zero(cur[tpre_lo(SELL_PRICE_WORD + 1) + 1]);
    debug_assert_eq!(INPUT_SELL_ID_OFF, 11 * 4 + 3);
    debug_assert_eq!(INPUT_SELL_INST_OFF, 15 * 4 + 3);
    debug_assert_eq!(INPUT_SELL_SIDE_OFF, 16 * 4 + 3);
    w.assert_eq(
        cur[tpre_lo(11) + 1],
        AB::Expr::from(field(MAKER_ORDER_ID_BYTE * TAKE_PACK)),
    );
    for word in 12..15 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(15)]);
    w.assert_eq(
        cur[tpre_lo(15) + 1],
        AB::Expr::from(field(INSTRUMENT_ID_BYTE * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(16)]);
    w.assert_eq(
        cur[tpre_lo(16) + 1],
        AB::Expr::from(field(SELL_SIDE_BYTE * TAKE_PACK)),
    );
    debug_assert_eq!(INPUT_TAKE_ID_OFF, TAKE_ID_WORD * 4);
    debug_assert_eq!(INPUT_TAKE_INST_OFF, TAKE_INST_WORD * 4);
    w.assert_eq(cur[tpre_lo(TAKE_ID_WORD)], AB::Expr::from(field(TAKER_ORDER_ID_BYTE)));
    w.assert_zero(cur[tpre_lo(TAKE_ID_WORD) + 1]);
    for word in TAKE_ID_WORD + 1..TAKE_INST_WORD {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_eq(cur[tpre_lo(TAKE_INST_WORD)], AB::Expr::from(field(INSTRUMENT_ID_BYTE)));
    w.assert_zero(cur[tpre_lo(TAKE_INST_WORD) + 1]);
    debug_assert_eq!(INPUT_SELL_EXPIRY_OFF, 29 * 4);
    debug_assert_eq!(INPUT_SELL_NONCE_OFF, 31 * 4);
    w.assert_eq(cur[tpre_lo(29)], AB::Expr::from(field(EXPIRY_HEIGHT)));
    w.assert_zero(cur[tpre_lo(29) + 1]);
    w.assert_zero(cur[tpre_lo(30)]);
    w.assert_zero(cur[tpre_lo(30) + 1]);
    w.assert_eq(cur[tpre_lo(31)], AB::Expr::from(field(ORDER_NONCE)));
    w.assert_zero(cur[tpre_lo(31) + 1]);
    w.assert_zero(cur[tpre_lo(32)]);
    w.assert_zero(cur[tpre_lo(32) + 1]);
}

/// 233 B `I` (`q41`): `INPUT_DOMAIN`, version, payload_len 206, count 2,
/// both Places `INPLACE`+`ORDER`. Sell id already occupies word 11 hi.
fn eval_bind_i_header<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    debug_assert_eq!(commitments::INPUT_DOMAIN.len(), NODE_DOMAIN_LEN);
    debug_assert_eq!(INPUT_PLACE0_OFF, 7 * 4 + 3);
    debug_assert_eq!(INPUT_ORDER0_OFF, 9 * 4 + 3);
    debug_assert_eq!(INPUT_SELL_ID_OFF, INPUT_ORDER0_OFF + 8);
    debug_assert_eq!(INPUT_PLACE1_OFF, 33 * 4);
    debug_assert_eq!(INPUT_ORDER1_OFF, 35 * 4);
    debug_assert_eq!(INPUT_TAKE_ID_OFF, INPUT_ORDER1_OFF + 8);
    debug_assert_eq!(
        NODE_DOMAIN_LEN + 2 + 8 + INPUT_PAYLOAD_LEN as usize,
        INPUT_COMMIT_BYTES
    );
    eval_bind_domain16(builder, cur[COL_Q41], cur, commitments::INPUT_DOMAIN);
    let mut w = builder.when(cur[COL_Q41]);
    let domain = commitments::INPUT_DOMAIN;
    let place = INPUT_PLACE_TAG;
    let order = INPUT_ORDER_TAG;
    w.assert_eq(
        cur[tpre_lo(4)],
        AB::Expr::from(field(
            domain[16] as u64 | (protocol_types::ENCODING_VERSION as u64) << 8,
        )),
    );
    w.assert_eq(
        cur[tpre_lo(4) + 1],
        AB::Expr::from(field(INPUT_PAYLOAD_LEN * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(5)]);
    w.assert_zero(cur[tpre_lo(5) + 1]);
    w.assert_zero(cur[tpre_lo(6)]);
    w.assert_eq(
        cur[tpre_lo(6) + 1],
        AB::Expr::from(field(INPUT_COUNT * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(7)]);
    w.assert_eq(
        cur[tpre_lo(7) + 1],
        AB::Expr::from(field(place[0] as u64 * TAKE_PACK)),
    );
    w.assert_eq(
        cur[tpre_lo(8)],
        AB::Expr::from(field(place[1] as u64 | (place[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(8) + 1],
        AB::Expr::from(field(place[3] as u64 | (place[4] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(9)],
        AB::Expr::from(field(place[5] as u64 | (place[6] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(9) + 1],
        AB::Expr::from(field(place[7] as u64 | (order[0] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(10)],
        AB::Expr::from(field(order[1] as u64 | (order[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(10) + 1],
        AB::Expr::from(field(order[3] as u64 | (order[4] as u64) << 8)),
    );
    w.assert_zero(cur[tpre_lo(11)]);
    w.assert_eq(
        cur[tpre_lo(33)],
        AB::Expr::from(field(place[0] as u64 | (place[1] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(33) + 1],
        AB::Expr::from(field(place[2] as u64 | (place[3] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(34)],
        AB::Expr::from(field(place[4] as u64 | (place[5] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(34) + 1],
        AB::Expr::from(field(place[6] as u64 | (place[7] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(35)],
        AB::Expr::from(field(order[0] as u64 | (order[1] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(35) + 1],
        AB::Expr::from(field(order[2] as u64 | (order[3] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(36)],
        AB::Expr::from(field(order[4] as u64)),
    );
    w.assert_zero(cur[tpre_lo(36) + 1]);
}

/// Both 244 B INC openings (`q52`): `INC_DOMAIN` (15 B), version, `height` tag,
/// Height encode len 8. Genesis and post share this prefix; `next_time` diverges.
fn eval_bind_inc_domain<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    debug_assert_eq!(commitments::INC_DOMAIN.len(), INC_DOMAIN_LEN);
    debug_assert_eq!(INC_HEIGHT_TAG_OFF, INC_DOMAIN_LEN + 2);
    debug_assert_eq!(INC_HEIGHT_OFF, INC_HEIGHT_TAG_OFF + INC_HEIGHT_TAG.len() + 8);
    let d = commitments::INC_DOMAIN;
    let tag = INC_HEIGHT_TAG;
    let mut w = builder.when(cur[COL_Q52]);
    for i in 0..3 {
        let off = 4 * i;
        w.assert_eq(
            cur[tpre_lo(i)],
            AB::Expr::from(field(d[off] as u64 | (d[off + 1] as u64) << 8)),
        );
        w.assert_eq(
            cur[tpre_lo(i) + 1],
            AB::Expr::from(field(d[off + 2] as u64 | (d[off + 3] as u64) << 8)),
        );
    }
    w.assert_eq(
        cur[tpre_lo(3)],
        AB::Expr::from(field(d[12] as u64 | (d[13] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(3) + 1],
        AB::Expr::from(field(
            d[14] as u64 | (protocol_types::ENCODING_VERSION as u64) << 8,
        )),
    );
    w.assert_eq(
        cur[tpre_lo(4)],
        AB::Expr::from(field((tag[0] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(4) + 1],
        AB::Expr::from(field(tag[1] as u64 | (tag[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(5)],
        AB::Expr::from(field(tag[3] as u64 | (tag[4] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(5) + 1],
        AB::Expr::from(field(tag[5] as u64 | INC_HEIGHT_LEN << 8)),
    );
}

/// This crossing: four deltas, taker buy. Base amounts = fill (10); quote
/// amounts = notional (900). Alignments rotate 1,2,3,0. Fill < 256 so the
/// odd-aligned packs are `v << 8`. Debits 0,1,1,0. Not a CLOB apply.
fn eval_bind_settlement<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    debug_assert_eq!(settle_amt_off(0), 77);
    debug_assert_eq!(settle_amt_off(1), 138);
    debug_assert_eq!(settle_amt_off(2), 199);
    debug_assert_eq!(settle_amt_off(3), 260);
    debug_assert_eq!(settle_debit_off(2), 215);
    debug_assert_eq!(settle_debit_off(3), 276);
    debug_assert_eq!(SETTLE_FILL_AMT, 10);
    debug_assert_eq!(SETTLE_QUOTE_AMT, 900);
    debug_assert_eq!(settle_owner_off(0), 41);
    debug_assert_eq!(settle_owner_off(3), 224);
    debug_assert_eq!(settle_asset_off(0), 73);
    debug_assert_eq!(settle_asset_off(3), 256);
    let q21 = cur[COL_Q21];
    let fill = cur[H_WIDTH + 4];
    let notional = cur[H_WIDTH + 7];
    let pack = AB::Expr::from(field(TAKE_PACK));
    let mut w = builder.when(q21);
    w.assert_eq(cur[tpre_lo(19)], fill * pack.clone());
    w.assert_zero(cur[tpre_lo(19) + 1]);
    for word in 20..23 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(23)]);
    w.assert_zero(cur[tpre_lo(34)]);
    w.assert_eq(cur[tpre_lo(34) + 1], notional);
    for word in 35..38 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(38)]);
    w.assert_zero(cur[tpre_lo(49)]);
    w.assert_eq(cur[tpre_lo(49) + 1], fill * pack);
    for word in 50..53 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(53)]);
    w.assert_eq(cur[tpre_lo(53) + 1], AB::Expr::from(field(TAKE_PACK)));
    w.assert_eq(cur[tpre5_lo(1)], notional);
    w.assert_zero(cur[tpre5_lo(1) + 1]);
    for word in 2..5 {
        w.assert_zero(cur[tpre5_lo(word)]);
        w.assert_zero(cur[tpre5_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre5_lo(5)]);
    w.assert_zero(cur[tpre5_lo(5) + 1]);
    w.assert_eq(
        cur[tpre_lo(10)],
        AB::Expr::from(field(TAKER_OWNER_BYTE * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(10) + 1]);
    for word in 11..18 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_eq(cur[tpre_lo(18)], AB::Expr::from(field(BASE_ASSET * TAKE_PACK)));
    w.assert_zero(cur[tpre_lo(18) + 1]);
    w.assert_zero(cur[tpre_lo(25)]);
    w.assert_eq(cur[tpre_lo(25) + 1], AB::Expr::from(field(TAKER_OWNER_BYTE)));
    for word in 26..33 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(33)]);
    w.assert_eq(cur[tpre_lo(33) + 1], AB::Expr::from(field(QUOTE_ASSET)));
    w.assert_zero(cur[tpre_lo(40)]);
    w.assert_eq(
        cur[tpre_lo(40) + 1],
        AB::Expr::from(field(MAKER_OWNER_BYTE * TAKE_PACK)),
    );
    for word in 41..48 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(48)]);
    w.assert_eq(cur[tpre_lo(48) + 1], AB::Expr::from(field(BASE_ASSET * TAKE_PACK)));
    w.assert_eq(cur[tpre_lo(56)], AB::Expr::from(field(MAKER_OWNER_BYTE)));
    w.assert_zero(cur[tpre_lo(56) + 1]);
    for word in 57..64 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_eq(cur[tpre5_lo(0)], AB::Expr::from(field(QUOTE_ASSET)));
    w.assert_zero(cur[tpre5_lo(0) + 1]);
}

/// 277 B settlement (`q21`): `RECEIPT_DOMAIN` (19 B), version, payload_len 248,
/// count 4, four `DELTA` tags. Delta 1 debit=1 shares word 38 hi with tag `D`.
fn eval_bind_receipt_header<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    debug_assert_eq!(commitments::RECEIPT_DOMAIN.len(), RECEIPT_DOMAIN_LEN);
    debug_assert_eq!(
        RECEIPT_DOMAIN_LEN + 2 + 8 + RECEIPT_COUNT as usize * SETTLE_DELTA_LEN + 4,
        SETTLEMENT_COMMIT_BYTES
    );
    debug_assert_eq!(
        RECEIPT_DOMAIN_LEN + 2 + 8 + 4,
        SETTLE_DELTA0_OFF
    );
    eval_bind_domain16(builder, cur[COL_Q21], cur, commitments::RECEIPT_DOMAIN);
    let mut w = builder.when(cur[COL_Q21]);
    let d = commitments::RECEIPT_DOMAIN;
    let tag = RECEIPT_DELTA_TAG;
    w.assert_eq(
        cur[tpre_lo(4)],
        AB::Expr::from(field(d[16] as u64 | (d[17] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(4) + 1],
        AB::Expr::from(field(
            d[18] as u64 | (protocol_types::ENCODING_VERSION as u64) << 8,
        )),
    );
    w.assert_eq(
        cur[tpre_lo(5)],
        AB::Expr::from(field(RECEIPT_PAYLOAD_LEN * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(5) + 1]);
    w.assert_zero(cur[tpre_lo(6)]);
    w.assert_zero(cur[tpre_lo(6) + 1]);
    w.assert_eq(
        cur[tpre_lo(7)],
        AB::Expr::from(field(RECEIPT_COUNT * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(7) + 1]);
    w.assert_eq(
        cur[tpre_lo(8)],
        AB::Expr::from(field((tag[0] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(8) + 1],
        AB::Expr::from(field(tag[1] as u64 | (tag[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(9)],
        AB::Expr::from(field(tag[3] as u64 | (tag[4] as u64) << 8)),
    );
    w.assert_zero(cur[tpre_lo(9) + 1]);
    w.assert_eq(
        cur[tpre_lo(23) + 1],
        AB::Expr::from(field(tag[0] as u64 | (tag[1] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(24)],
        AB::Expr::from(field(tag[2] as u64 | (tag[3] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(24) + 1],
        AB::Expr::from(field(tag[4] as u64)),
    );
    w.assert_eq(
        cur[tpre_lo(38) + 1],
        AB::Expr::from(field(SETTLE_DEBIT1 | (tag[0] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(39)],
        AB::Expr::from(field(tag[1] as u64 | (tag[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(39) + 1],
        AB::Expr::from(field(tag[3] as u64 | (tag[4] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(54)],
        AB::Expr::from(field(tag[0] as u64 | (tag[1] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(54) + 1],
        AB::Expr::from(field(tag[2] as u64 | (tag[3] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(55)],
        AB::Expr::from(field(tag[4] as u64)),
    );
    w.assert_zero(cur[tpre_lo(55) + 1]);
}

fn eval_hidx_flag<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    hidx: AB::Var,
    flag: AB::Var,
    inv: AB::Var,
    target: u64,
) {
    builder.assert_bool(flag);
    let d = hidx - AB::Expr::from(field(target));
    builder.assert_zero(flag * d.clone());
    builder.assert_eq(inv * d + flag, AB::Expr::ONE);
}

fn eval_pack8<AB: AirBuilder<F = Val>>(builder: &mut AB, bits: &[AB::Var]) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    let mut pow = AB::Expr::ONE;
    for &b in bits {
        builder.assert_bool(b);
        acc = acc + b.into() * pow.clone();
        pow = pow.clone() + pow;
    }
    acc
}

fn eval_digest_bytes<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    limbs: &[AB::Var],
    bits: &[AB::Var],
) -> [AB::Expr; 32] {
    debug_assert_eq!(limbs.len(), 16);
    debug_assert_eq!(bits.len(), 256);
    let mut bytes = core::array::from_fn(|_| AB::Expr::ZERO);
    for i in 0..16 {
        let b0 = eval_pack8(builder, &bits[i * 16..i * 16 + 8]);
        let b1 = eval_pack8(builder, &bits[i * 16 + 8..i * 16 + 16]);
        builder.assert_eq(
            limbs[i],
            b0.clone() + b1.clone() * AB::Expr::from(field(256)),
        );
        bytes[2 * i] = b0;
        bytes[2 * i + 1] = b1;
    }
    bytes
}

fn this_height_inc_header_words() -> [u32; INC_HEADER_WORDS] {
    let pre = fixture_inc_preimage(THIS_NEXT_TIME);
    debug_assert_eq!(
        &pre[INC_HEIGHT_OFF..INC_HEIGHT_OFF + 8],
        &THIS_HEIGHT.to_le_bytes()
    );
    debug_assert_eq!(
        &pre[INC_NEXT_T_OFF..INC_NEXT_T_OFF + 8],
        &THIS_NEXT_TIME.to_le_bytes()
    );
    let mut words = [0u32; INC_HEADER_WORDS];
    for (i, slot) in words.iter_mut().enumerate() {
        *slot = u32::from_le_bytes(pre[i * 4..i * 4 + 4].try_into().expect("4"));
    }
    words
}

fn genesis_inc_tpre_words() -> [u32; INC_TPRE_WORDS] {
    let pre = genesis_inc_preimage();
    let mut words = [0u32; INC_TPRE_WORDS];
    for (i, slot) in words.iter_mut().enumerate() {
        *slot = u32::from_le_bytes(pre[i * 4..i * 4 + 4].try_into().expect("4"));
    }
    words
}

fn eval_bind_q52_split<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    let q52 = cur[COL_Q52];
    let hlast = cur[COL_HLAST];
    let hidx = cur[COL_HIDX];
    let q52p = cur[COL_Q52P];
    let q52g = cur[COL_Q52G];
    let q52m = cur[COL_Q52M];
    let is14 = cur[COL_IS14];
    let is15 = cur[COL_IS15];
    eval_hidx_flag(builder, hidx, is14, cur[COL_I14INV], HIDX_GENESIS_INC);
    eval_hidx_flag(builder, hidx, is15, cur[COL_I15INV], HIDX_MID_INC);
    builder.assert_bool(q52p);
    builder.assert_bool(q52g);
    builder.assert_bool(q52m);
    builder.assert_zero(q52p * q52g);
    builder.assert_zero(q52p * q52m);
    builder.assert_zero(q52g * q52m);
    builder.assert_eq(q52p + q52g + q52m, q52);
    builder.assert_eq(q52p, q52 * hlast);
    builder.assert_eq(q52g, q52 * is14);
    builder.assert_eq(q52m, q52 * is15);
}

fn eval_bind_domain16<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    sel: AB::Var,
    cur: &[AB::Var],
    domain: &[u8],
) {
    debug_assert!(domain.len() >= 16);
    let mut w = builder.when(sel);
    for i in 0..4 {
        let off = 4 * i;
        w.assert_eq(
            cur[tpre_lo(i)],
            AB::Expr::from(field(domain[off] as u64 | (domain[off + 1] as u64) << 8)),
        );
        w.assert_eq(
            cur[tpre_lo(i) + 1],
            AB::Expr::from(field(domain[off + 2] as u64 | (domain[off + 3] as u64) << 8)),
        );
    }
}

fn eval_bind_q51_q11<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    let blast = cur[COL_BLAST];
    let q51 = cur[COL_Q51];
    let q11 = cur[COL_Q11];
    builder.assert_bool(q51);
    builder.assert_bool(q11);
    builder.assert_eq(q51, blast * cur[COL_NB + 1]);
    builder.assert_eq(q11, blast * cur[COL_NB + 2]);
}

/// All three 115 B seen openings: domain, version, key_len=16, value_len=0,
/// OrderId key tail zeros. First key byte by `hidx` (2 at 6, else 1).
fn eval_bind_seen_header<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    eval_bind_domain16(builder, cur[COL_Q51], cur, commitments::TREAP_NODE_DOMAIN);
    let mut w = builder.when(cur[COL_Q51]);
    let domain = commitments::TREAP_NODE_DOMAIN;
    w.assert_eq(
        cur[tpre_lo(4)],
        AB::Expr::from(field(
            domain[16] as u64 | (protocol_types::ENCODING_VERSION as u64) << 8,
        )),
    );
    w.assert_zero(cur[tpre_lo(13)]);
    w.assert_zero(cur[tpre_lo(13) + 1]);
    w.assert_zero(cur[tpre_lo(14)]);
    for word in 15..20 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(20)]);
}

/// All four 139 B nonce openings: domain, version, key_len=32, value_len=8,
/// OwnerId key tail zeros, value `ORDER_NONCE`. First key byte by `hidx`
/// (2 at 3 and 5, else 1).
fn eval_bind_nonce_header<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    eval_bind_domain16(builder, cur[COL_Q11], cur, commitments::TREAP_NODE_DOMAIN);
    let mut w = builder.when(cur[COL_Q11]);
    let domain = commitments::TREAP_NODE_DOMAIN;
    debug_assert_eq!(NONCE_VALUE_OFF, 24 * 4 + 3);
    w.assert_eq(
        cur[tpre_lo(4)],
        AB::Expr::from(field(
            domain[16] as u64 | (protocol_types::ENCODING_VERSION as u64) << 8,
        )),
    );
    w.assert_zero(cur[tpre_lo(13)]);
    w.assert_zero(cur[tpre_lo(13) + 1]);
    w.assert_zero(cur[tpre_lo(14)]);
    for word in 15..22 {
        w.assert_zero(cur[tpre_lo(word)]);
        w.assert_zero(cur[tpre_lo(word) + 1]);
    }
    w.assert_zero(cur[tpre_lo(22)]);
    w.assert_eq(
        cur[tpre_lo(22) + 1],
        AB::Expr::from(field(NONCE_VALUE_LEN * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(23)]);
    w.assert_zero(cur[tpre_lo(23) + 1]);
    w.assert_zero(cur[tpre_lo(24)]);
    w.assert_eq(
        cur[tpre_lo(24) + 1],
        AB::Expr::from(field(ORDER_NONCE * TAKE_PACK)),
    );
    w.assert_zero(cur[tpre_lo(25)]);
    w.assert_zero(cur[tpre_lo(25) + 1]);
    w.assert_zero(cur[tpre_lo(26)]);
}

/// Empty child at align-3 (byte `4*word0+3`). `suffix` occupies the next byte.
fn eval_bind_empty_align3<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    sel: AB::Var,
    cur: &[AB::Var],
    word0: usize,
    suffix: u64,
) {
    eval_bind_empty_align3_pre(builder, sel.into(), cur, COL_TPRE, word0, suffix);
}

fn eval_bind_empty_align3_pre<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    sel: AB::Expr,
    cur: &[AB::Var],
    pre_base: usize,
    word0: usize,
    suffix: u64,
) {
    let col = |w: usize| pre_base + 2 * w;
    let empty = commitments::treap_empty_digest().0;
    let mut w = builder.when(sel);
    w.assert_eq(
        cur[col(word0) + 1],
        AB::Expr::from(field(empty[0] as u64 * TAKE_PACK)),
    );
    for i in 0..7 {
        let off = 1 + 4 * i;
        let word = word0 + 1 + i;
        w.assert_eq(
            cur[col(word)],
            AB::Expr::from(field(empty[off] as u64 | (empty[off + 1] as u64) << 8)),
        );
        w.assert_eq(
            cur[col(word) + 1],
            AB::Expr::from(field(empty[off + 2] as u64 | (empty[off + 3] as u64) << 8)),
        );
    }
    let last = word0 + 8;
    w.assert_eq(
        cur[col(last)],
        AB::Expr::from(field(empty[29] as u64 | (empty[30] as u64) << 8)),
    );
    w.assert_eq(
        cur[col(last) + 1],
        AB::Expr::from(field(empty[31] as u64 | suffix << 8)),
    );
}

/// Empty 32 B child at word-aligned `word0` (resting right).
fn eval_bind_empty_words_pre<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    sel: AB::Expr,
    cur: &[AB::Var],
    pre_base: usize,
    word0: usize,
) {
    let col = |w: usize| pre_base + 2 * w;
    let empty = commitments::treap_empty_digest().0;
    let empty_w = words32(&empty);
    let mut w = builder.when(sel);
    for i in 0..8 {
        w.assert_eq(
            cur[col(word0 + i)],
            AB::Expr::from(field(lo(empty_w[i]) as u64)),
        );
        w.assert_eq(
            cur[col(word0 + i) + 1],
            AB::Expr::from(field(hi(empty_w[i]) as u64)),
        );
    }
}

/// Word-aligned child digest: 8×u32 LE as 16 limbs (same layout as `NCVO`).
fn eval_bind_child_words_pre<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    sel: AB::Expr,
    cur: &[AB::Var],
    pre_base: usize,
    word0: usize,
    dig: &[AB::Var],
) {
    debug_assert_eq!(dig.len(), 16);
    let col = |w: usize| pre_base + 2 * w;
    let mut w = builder.when(sel);
    for i in 0..8 {
        w.assert_eq(cur[col(word0 + i)], dig[2 * i]);
        w.assert_eq(cur[col(word0 + i) + 1], dig[2 * i + 1]);
    }
}

/// Seen right empty on all four 115 B; seen left empty except hidx 8.
/// Nonce right empty on all four 139 B; nonce left empty except hidx 5.
fn eval_bind_seen_nonce_children<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    debug_assert_eq!(RESTING_LEFT_OFF, 19);
    debug_assert_eq!(SEEN_RIGHT_OFF, 20 * 4 + 3);
    debug_assert_eq!(NONCE_RIGHT_OFF, 26 * 4 + 3);
    let q51 = cur[COL_Q51];
    let q11 = cur[COL_Q11];
    // COL_SEEN_RE reused as seen-left-empty selector (except rotate root).
    let seen_le = cur[COL_SEEN_RE];
    let nonce_le = cur[COL_NONCE_LE];
    builder.assert_bool(seen_le);
    builder.assert_bool(nonce_le);
    builder.assert_eq(seen_le, q51 * (AB::Expr::ONE - cur[COL_IS8]));
    builder.assert_eq(nonce_le, q11 * (AB::Expr::ONE - cur[COL_IS5]));
    eval_bind_empty_align3(builder, seen_le, cur, 4, RESTING_KEY_LEN);
    eval_bind_empty_align3(builder, q51, cur, 20, 0);
    eval_bind_empty_align3(builder, q11, cur, 26, 0);
    eval_bind_empty_align3(builder, nonce_le, cur, 4, NONCE_KEY_LEN);
}

fn eval_bind_child_align3<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    sel: AB::Var,
    cur: &[AB::Var],
    word0: usize,
    suffix: u64,
    bytes: &[AB::Expr; 32],
) {
    eval_bind_child_align3_pre(builder, sel.into(), cur, COL_TPRE, word0, suffix, bytes);
}

fn eval_bind_child_align3_pre<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    sel: AB::Expr,
    cur: &[AB::Var],
    pre_base: usize,
    word0: usize,
    suffix: u64,
    bytes: &[AB::Expr; 32],
) {
    let col = |w: usize| pre_base + 2 * w;
    let pack = AB::Expr::from(field(TAKE_PACK));
    let mut w = builder.when(sel);
    w.assert_eq(cur[col(word0) + 1], bytes[0].clone() * pack.clone());
    for i in 0..7 {
        let off = 1 + 4 * i;
        let word = word0 + 1 + i;
        w.assert_eq(
            cur[col(word)],
            bytes[off].clone() + bytes[off + 1].clone() * pack.clone(),
        );
        w.assert_eq(
            cur[col(word) + 1],
            bytes[off + 2].clone() + bytes[off + 3].clone() * pack.clone(),
        );
    }
    let last = word0 + 8;
    w.assert_eq(
        cur[col(last)],
        bytes[29].clone() + bytes[30].clone() * pack.clone(),
    );
    w.assert_eq(
        cur[col(last) + 1],
        bytes[31].clone() + AB::Expr::from(field(suffix)) * pack,
    );
}

/// Nonce root left (hidx 9) = opening 8 `out`.
/// Seen root left (hidx 13) = demoted opening 12 `out` (≡ opening 3).
fn eval_bind_sibling_children<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
) {
    debug_assert_eq!(HIDX_NONCE_PREV, 8);
    debug_assert_eq!(HIDX_SEEN_DEMOT, 12);
    let hidx = cur[COL_HIDX];
    eval_hidx_flag(builder, hidx, cur[COL_IS4], cur[COL_I4INV], HIDX_NONCE_PREV);
    eval_hidx_flag(builder, hidx, cur[COL_IS7], cur[COL_I7INV], HIDX_SEEN_DEMOT);
    let is4 = cur[COL_IS4];
    let is7 = cur[COL_IS7];
    let is4r = cur[COL_IS4R];
    let is7r = cur[COL_IS7R];
    let rootn = cur[COL_ROOTN];
    builder.assert_bool(is4r);
    builder.assert_bool(is7r);
    builder.assert_eq(is4r, is4 * rootn);
    builder.assert_eq(is7r, is7 * rootn);
    for i in 0..16 {
        builder.assert_zero(is4r * (cur[COL_LAT4 + i] - cur[COL_NCVO + i]));
        builder.assert_zero(is7r * (cur[COL_LAT6 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_LAT4 + i]);
            first.assert_zero(cur[COL_LAT6 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep4 = AB::Expr::ONE - nxt[COL_IS4R];
        let keep7 = AB::Expr::ONE - nxt[COL_IS7R];
        for i in 0..16 {
            t.assert_zero(keep4.clone() * (nxt[COL_LAT4 + i] - cur[COL_LAT4 + i]));
            t.assert_zero(keep7.clone() * (nxt[COL_LAT6 + i] - cur[COL_LAT6 + i]));
        }
    }
    let n4 = eval_digest_bytes(
        builder,
        &cur[COL_LAT4..COL_LAT4 + 16],
        &cur[COL_B4..COL_B4 + 256],
    );
    let s7 = eval_digest_bytes(
        builder,
        &cur[COL_LAT6..COL_LAT6 + 16],
        &cur[COL_B6..COL_B6 + 256],
    );
    eval_bind_child_align3(builder, cur[COL_IS5R], cur, 4, NONCE_KEY_LEN, &n4);
    // Seen rotate root: left ← demoted (key len 16).
    eval_bind_child_align3(builder, cur[COL_IS8R], cur, 4, RESTING_KEY_LEN, &s7);
}

/// Demote out pins: `out(12)=out(3)` (seen) and `out(1)=out(8)` (nonce).
/// Closes rotate/mid: mid seen = demoted = left of 8; mid nonce latch = first
/// nonce leaf. Full preimages `7≡1` / `0≡4` hold natively; AIR pins outs.
fn eval_bind_demote_pin<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
) {
    let hidx = cur[COL_HIDX];
    eval_hidx_flag(builder, hidx, cur[COL_IS0], cur[COL_I0INV], HIDX_NONCE_FIRST);
    let is0 = cur[COL_IS0];
    let is0r = cur[COL_IS0R];
    let rootn = cur[COL_ROOTN];
    builder.assert_bool(is0r);
    builder.assert_eq(is0r, is0 * rootn);
    for i in 0..16 {
        builder.assert_zero(is0r * (cur[COL_LAT0 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_LAT0 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_IS0R];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_LAT0 + i] - cur[COL_LAT0 + i]));
        }
    }
    let is8r = cur[COL_IS8R];
    let is5r = cur[COL_IS5R];
    for i in 0..16 {
        builder.assert_zero(is8r * (cur[COL_LAT6 + i] - cur[COL_LAT1 + i]));
        builder.assert_zero(is5r * (cur[COL_LAT4 + i] - cur[COL_LAT0 + i]));
    }
}

/// BST on edges `9←8` / `13←12`: left child key < parent on both.
/// Latch key bytes from openings 4 / 7; compare on parent root rows.
/// Not full rotate algebra; not `F`.
/// Place1+Place2 insert keys. Latch OrderId/OwnerId from prios; bind map keys
/// and `I` sell/take id/owner first bytes. Not full insert walk; not `F`.
fn eval_bind_insert_from_i<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
) {
    let pack = AB::Expr::from(field(TAKE_PACK));
    let rootn = cur[COL_ROOTN];
    let q33 = cur[COL_Q33];
    let q49 = cur[COL_Q49];
    let q41 = cur[COL_Q41];
    let q24 = cur[COL_Q24];
    let hidx = cur[COL_HIDX];
    eval_hidx_flag(builder, hidx, cur[COL_IS2], cur[COL_I2INV], HIDX_ORDER_K1);
    let is12 = cur[COL_IS12];
    let is11 = cur[COL_IS11];
    let is2 = cur[COL_IS2];
    let is3 = cur[COL_IS3];
    let is6 = cur[COL_IS6];
    let load_tid = cur[COL_LOAD_TID];
    let load_town = cur[COL_LOAD_TOWN];
    let load_sid = cur[COL_LOAD_SID];
    let load_sown = cur[COL_LOAD_SOWN];
    let load_rp = cur[COL_LOAD_RP];
    let is3r = cur[COL_IS3R];
    let is6r = cur[COL_IS6R];
    builder.assert_bool(load_tid);
    builder.assert_bool(load_town);
    builder.assert_bool(load_sid);
    builder.assert_bool(load_sown);
    builder.assert_bool(load_rp);
    builder.assert_bool(is3r);
    builder.assert_bool(is6r);
    // Place2 loads.
    builder.assert_eq(load_tid, q33 * is12 * rootn);
    builder.assert_eq(load_town, q49 * is11 * rootn);
    // Place1 loads: order prio hidx 2; owner prio hidx 0 (= q49 ∧ ¬is11).
    builder.assert_eq(load_sid, q33 * is2 * rootn);
    builder.assert_eq(load_sown, q49 * (AB::Expr::ONE - is11) * rootn);
    // Resting order prio (hidx 4): sole remaining q33 among {2,4,10}.
    builder.assert_eq(load_rp, q33 * (AB::Expr::ONE - is2 - is12) * rootn);
    builder.assert_eq(is3r, is3 * rootn);
    builder.assert_eq(is6r, is6 * rootn);
    let is0r = cur[COL_IS0R];
    let is1r = cur[COL_IS1R];
    let is4r = cur[COL_IS4R];
    let is5r = cur[COL_IS5R];
    let is7r = cur[COL_IS7R];
    let is8r = cur[COL_IS8R];
    let prio_lo = AB::Expr::from(field(commitments::TREAP_PRIO_DOMAIN[16] as u64));
    let w4 = cur[tpre_lo(4)];
    builder.assert_zero(load_tid * (cur[COL_LAT_TID0] * pack.clone() + prio_lo.clone() - w4));
    builder.assert_zero(load_town * (cur[COL_LAT_TOWN0] * pack.clone() + prio_lo.clone() - w4));
    builder.assert_zero(load_sid * (cur[COL_LAT_SID0] * pack.clone() + prio_lo.clone() - w4));
    builder.assert_zero(load_sown * (cur[COL_LAT_SOWN0] * pack.clone() + prio_lo.clone() - w4));
    {
        let mut first = builder.when_first_row();
        // Place1 owner prio may load on row 0.
        first.assert_zero((AB::Expr::ONE - load_sown) * cur[COL_LAT_SOWN0]);
        first.assert_zero(cur[COL_LAT_SID0]);
        first.assert_zero(cur[COL_LAT_TID0]);
        first.assert_zero(cur[COL_LAT_TOWN0]);
    }
    {
        let mut t = builder.when_transition();
        t.assert_zero((AB::Expr::ONE - nxt[COL_LOAD_TID]) * (nxt[COL_LAT_TID0] - cur[COL_LAT_TID0]));
        t.assert_zero(
            (AB::Expr::ONE - nxt[COL_LOAD_TOWN]) * (nxt[COL_LAT_TOWN0] - cur[COL_LAT_TOWN0]),
        );
        t.assert_zero((AB::Expr::ONE - nxt[COL_LOAD_SID]) * (nxt[COL_LAT_SID0] - cur[COL_LAT_SID0]));
        t.assert_zero(
            (AB::Expr::ONE - nxt[COL_LOAD_SOWN]) * (nxt[COL_LAT_SOWN0] - cur[COL_LAT_SOWN0]),
        );
    }
    let map_key0 = cur[tpre_lo(14) + 1];
    // Place2 seen/nonce roots+leaves.
    builder.assert_zero(is6r * (map_key0.clone() - cur[COL_LAT_TID0] * pack.clone()));
    builder.assert_zero(is8r * (map_key0.clone() - cur[COL_LAT_TID0] * pack.clone()));
    builder.assert_zero(is3r * (map_key0.clone() - cur[COL_LAT_TOWN0] * pack.clone()));
    builder.assert_zero(is5r * (map_key0.clone() - cur[COL_LAT_TOWN0] * pack.clone()));
    // Place1 seen/nonce first+demote.
    builder.assert_zero(is1r * (map_key0.clone() - cur[COL_LAT_SID0] * pack.clone()));
    builder.assert_zero(is7r * (map_key0.clone() - cur[COL_LAT_SID0] * pack.clone()));
    builder.assert_zero(is0r * (map_key0.clone() - cur[COL_LAT_SOWN0] * pack.clone()));
    builder.assert_zero(is4r * (map_key0 - cur[COL_LAT_SOWN0] * pack.clone()));
    // Resting OrderId first byte (align-3 at word 22) + owner (word 32).
    builder.assert_zero(q24 * (cur[tpre_lo(22) + 1] - cur[COL_LAT_SID0] * pack.clone()));
    builder.assert_zero(q24 * (cur[tpre_lo(32)] - cur[COL_LAT_SOWN0]));
    // Resting-map order prio key0 = Place1 sell id latch.
    builder.assert_zero(load_rp * (w4.clone() - cur[COL_LAT_SID0] * pack.clone() - prio_lo.clone()));
    let i_root = q41 * rootn;
    // Place2 `I` take id / owner.
    builder.assert_zero(i_root.clone() * (cur[tpre_lo(TAKE_ID_WORD)] - cur[COL_LAT_TID0]));
    builder.assert_zero(i_root.clone() * (cur[tpre_lo(46)] - cur[COL_LAT_TOWN0] * pack.clone()));
    // Place1 `I` sell id (align-3) / sell owner (word-aligned).
    builder.assert_zero(i_root.clone() * (cur[tpre_lo(11) + 1] - cur[COL_LAT_SID0] * pack.clone()));
    builder.assert_zero(i_root * (cur[tpre_lo(21)] - cur[COL_LAT_SOWN0]));
}

fn eval_bind_bst_edges<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
) {
    let pack = AB::Expr::from(field(TAKE_PACK));
    let is4r = cur[COL_IS4R];
    let is5r = cur[COL_IS5R];
    let is7r = cur[COL_IS7R];
    let is8r = cur[COL_IS8R];
    let key_packed = cur[tpre_lo(14) + 1];
    builder.assert_zero(is4r * (cur[COL_LAT_K4] * pack.clone() - key_packed));
    builder.assert_zero(is7r * (cur[COL_LAT_K6] * pack.clone() - key_packed));
    {
        let mut first = builder.when_first_row();
        first.assert_zero(cur[COL_LAT_K4]);
        first.assert_zero(cur[COL_LAT_K6]);
    }
    {
        let mut t = builder.when_transition();
        let keep4 = AB::Expr::ONE - nxt[COL_IS4R];
        let keep7 = AB::Expr::ONE - nxt[COL_IS7R];
        t.assert_zero(keep4 * (nxt[COL_LAT_K4] - cur[COL_LAT_K4]));
        t.assert_zero(keep7 * (nxt[COL_LAT_K6] - cur[COL_LAT_K6]));
    }
    let diff_n = eval_pack8(builder, &cur[COL_BST_ND..COL_BST_ND + 8]);
    let diff_s = eval_pack8(builder, &cur[COL_BST_SD..COL_BST_SD + 8]);
    // key5 - key4 - 1 = diff_n
    {
        let mut w = builder.when(is5r);
        w.assert_eq(
            key_packed,
            pack.clone() * (diff_n + cur[COL_LAT_K4] + AB::Expr::ONE),
        );
    }
    // key8 - key7 - 1 = diff_s (left child < rotate root)
    {
        let mut w = builder.when(is8r);
        w.assert_eq(
            key_packed,
            pack * (diff_s + cur[COL_LAT_K6] + AB::Expr::ONE),
        );
    }
}

/// Order and owner prio share `TREAP_PRIO_DOMAIN`. First key byte by `hidx`
/// (order 5 at 13, owner 2 at 12, else 1).
fn eval_bind_prio_header<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    let q33 = cur[COL_Q33];
    let q49 = cur[COL_Q49];
    eval_bind_domain16(builder, q33, cur, commitments::TREAP_PRIO_DOMAIN);
    eval_bind_domain16(builder, q49, cur, commitments::TREAP_PRIO_DOMAIN);
    {
        let mut w = builder.when(q33 + q49);
        w.assert_zero(cur[tpre_lo(4) + 1]);
    }
    {
        let mut w = builder.when(q33);
        for word in 5..9 {
            w.assert_zero(cur[tpre_lo(word)]);
            w.assert_zero(cur[tpre_lo(word) + 1]);
        }
    }
    {
        let mut w = builder.when(q49);
        for word in 5..13 {
            w.assert_zero(cur[tpre_lo(word)]);
            w.assert_zero(cur[tpre_lo(word) + 1]);
        }
    }
}

/// First key byte on this rotate fixture: seen ∈ {1,5} via `1+4·k5`,
/// nonce/owner ∈ {1,2} via `1+k2`, order prio ∈ {1,5} via `1+4·k5`.
/// k5 flags: seen leaf 6 + seen root 8 + order prio 13. Degree 2.
fn eval_bind_unique_keys<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    let hidx = cur[COL_HIDX];
    eval_hidx_flag(builder, hidx, cur[COL_IS3], cur[COL_I3INV], HIDX_NONCE_K2);
    eval_hidx_flag(builder, hidx, cur[COL_IS6], cur[COL_I6INV], HIDX_SEEN_K5);
    eval_hidx_flag(builder, hidx, cur[COL_IS8], cur[COL_I8INV], HIDX_SEEN_ROOT);
    eval_hidx_flag(builder, hidx, cur[COL_IS11], cur[COL_I11INV], HIDX_OWNER_K2);
    eval_hidx_flag(builder, hidx, cur[COL_IS12], cur[COL_I12INV], HIDX_ORDER_K5);
    let q51 = cur[COL_Q51];
    let q11 = cur[COL_Q11];
    let q33 = cur[COL_Q33];
    let q49 = cur[COL_Q49];
    let is3 = cur[COL_IS3];
    let is5 = cur[COL_IS5];
    let is6 = cur[COL_IS6];
    let is8 = cur[COL_IS8];
    let is11 = cur[COL_IS11];
    let is12 = cur[COL_IS12];
    let pack = AB::Expr::from(field(TAKE_PACK));
    let four = AB::Expr::from(field(4));
    builder.assert_eq(
        q51 * cur[tpre_lo(14) + 1],
        q51 * pack.clone() * (AB::Expr::ONE + four.clone() * (is6 + is8)),
    );
    builder.assert_eq(
        q11 * cur[tpre_lo(14) + 1],
        q11 * pack.clone() * (AB::Expr::ONE + is3 + is5),
    );
    let prio_lo = AB::Expr::from(field(commitments::TREAP_PRIO_DOMAIN[16] as u64));
    builder.assert_eq(
        q33 * cur[tpre_lo(4)],
        q33 * (prio_lo.clone() + pack.clone() * (AB::Expr::ONE + four * is12)),
    );
    builder.assert_eq(
        q49 * cur[tpre_lo(4)],
        q49 * (prio_lo + pack * (AB::Expr::ONE + is11)),
    );
}

/// Range-check a 16-bit limb against 16 bool bits.
fn eval_limb16_bits<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    limb: AB::Var,
    bits: &[AB::Var],
) {
    debug_assert_eq!(bits.len(), 16);
    let mut acc = AB::Expr::ZERO;
    let mut pow = AB::Expr::ONE;
    for &b in bits {
        builder.assert_bool(b);
        acc = acc + b * pow.clone();
        pow = pow.clone() + pow;
    }
    builder.assert_eq(limb, acc);
}

/// Treap heap on edges `5←4` (OwnerId prio) and `8←7` (OrderId prio):
/// `priority` limbs = first four [`COL_NCVO`] limbs. Latch from `q49`/`q33`,
/// then `pn2 > pn1` and `po5 > po1` (rotate root). Not full rotate/insert; not `F`.
fn eval_bind_prio_heap<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
) {
    let q33 = cur[COL_Q33];
    let q49 = cur[COL_Q49];
    let is11 = cur[COL_IS11];
    let is12 = cur[COL_IS12];
    let rootn = cur[COL_ROOTN];
    // Latch only on digest root rows (not mid-compress IV).
    builder.assert_eq(cur[COL_LOAD_PN1], q49 * (AB::Expr::ONE - is11) * rootn);
    builder.assert_eq(cur[COL_LOAD_PN2], q49 * is11 * rootn);
    builder.assert_eq(cur[COL_LOAD_PO1], q33 * (AB::Expr::ONE - is12) * rootn);
    builder.assert_eq(cur[COL_LOAD_PO2], q33 * is12 * rootn);
    let load_pn1 = cur[COL_LOAD_PN1];
    let load_pn2 = cur[COL_LOAD_PN2];
    let load_po1 = cur[COL_LOAD_PO1];
    let load_po2 = cur[COL_LOAD_PO2];
    for i in 0..4 {
        let limb = cur[COL_NCVO + i];
        builder.assert_zero(load_pn1 * (cur[COL_LAT_PN1 + i] - limb));
        builder.assert_zero(load_pn2 * (cur[COL_LAT_PN2 + i] - limb));
        builder.assert_zero(load_po1 * (cur[COL_LAT_PO1 + i] - limb));
        builder.assert_zero(load_po2 * (cur[COL_LAT_PO2 + i] - limb));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..4 {
            first.assert_zero(cur[COL_LAT_PN1 + i]);
            first.assert_zero(cur[COL_LAT_PN2 + i]);
            first.assert_zero(cur[COL_LAT_PO1 + i]);
            first.assert_zero(cur[COL_LAT_PO2 + i]);
        }
        first.assert_zero(cur[COL_HEAP_STICKY]);
    }
    {
        let mut t = builder.when_transition();
        let keep_pn1 = AB::Expr::ONE - nxt[COL_LOAD_PN1];
        let keep_pn2 = AB::Expr::ONE - nxt[COL_LOAD_PN2];
        let keep_po1 = AB::Expr::ONE - nxt[COL_LOAD_PO1];
        let keep_po2 = AB::Expr::ONE - nxt[COL_LOAD_PO2];
        for i in 0..4 {
            t.assert_zero(keep_pn1.clone() * (nxt[COL_LAT_PN1 + i] - cur[COL_LAT_PN1 + i]));
            t.assert_zero(keep_pn2.clone() * (nxt[COL_LAT_PN2 + i] - cur[COL_LAT_PN2 + i]));
            t.assert_zero(keep_po1.clone() * (nxt[COL_LAT_PO1 + i] - cur[COL_LAT_PO1 + i]));
            t.assert_zero(keep_po2.clone() * (nxt[COL_LAT_PO2 + i] - cur[COL_LAT_PO2 + i]));
        }
        t.assert_zero(nxt[COL_HEAP_STICKY] - cur[COL_HEAP_RDY]);
    }
    let load = load_po2;
    builder.assert_bool(cur[COL_HEAP_STICKY]);
    builder.assert_bool(cur[COL_HEAP_RDY]);
    builder.assert_eq(
        cur[COL_HEAP_RDY],
        cur[COL_HEAP_STICKY] + load - cur[COL_HEAP_STICKY] * load,
    );
    // Always range-check diff bit witnesses; heap eqs only when ready.
    for i in 0..4 {
        let n0 = COL_HEAP_NDB + i * 16;
        let s0 = COL_HEAP_SDB + i * 16;
        eval_limb16_bits(builder, cur[COL_HEAP_ND + i], &cur[n0..n0 + 16]);
        eval_limb16_bits(builder, cur[COL_HEAP_SD + i], &cur[s0..s0 + 16]);
    }
    {
        let mut w = builder.when(cur[COL_HEAP_RDY]);
        let base = AB::Expr::from(field(LIMB as u64));
        // diff = a - b - borrow_in + borrow_out·2^16
        for i in 0..4 {
            w.assert_bool(cur[COL_HEAP_NB + i]);
            let borrow_in = if i == 0 {
                AB::Expr::ONE
            } else {
                cur[COL_HEAP_NB + i - 1].into()
            };
            if i < 3 {
                w.assert_eq(
                    cur[COL_HEAP_ND + i],
                    cur[COL_LAT_PN2 + i] - cur[COL_LAT_PN1 + i] - borrow_in
                        + cur[COL_HEAP_NB + i] * base.clone(),
                );
            } else {
                w.assert_zero(cur[COL_HEAP_NB + 3]);
                w.assert_eq(
                    cur[COL_HEAP_ND + i],
                    cur[COL_LAT_PN2 + i] - cur[COL_LAT_PN1 + i] - borrow_in,
                );
            }
        }
        for i in 0..4 {
            w.assert_bool(cur[COL_HEAP_SB + i]);
            let borrow_in = if i == 0 {
                AB::Expr::ONE
            } else {
                cur[COL_HEAP_SB + i - 1].into()
            };
            if i < 3 {
                w.assert_eq(
                    cur[COL_HEAP_SD + i],
                    cur[COL_LAT_PO2 + i] - cur[COL_LAT_PO1 + i] - borrow_in
                        + cur[COL_HEAP_SB + i] * base.clone(),
                );
            } else {
                w.assert_zero(cur[COL_HEAP_SB + 3]);
                w.assert_eq(
                    cur[COL_HEAP_SD + i],
                    cur[COL_LAT_PO2 + i] - cur[COL_LAT_PO1 + i] - borrow_in,
                );
            }
        }
    }
}

/// Post INC (`q52p`): `height=1`, `next_time=1`, genesis instruments.
fn eval_bind_inc_header<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    // Post and mid share height/next_time/instruments; genesis is pinned fully.
    let mut w = builder.when(cur[COL_Q52P] + cur[COL_Q52M]);
    let words = this_height_inc_header_words();
    for (i, word) in words.iter().enumerate() {
        w.assert_eq(cur[tpre_lo(i)], AB::Expr::from(field(lo(*word) as u64)));
        w.assert_eq(cur[tpre_lo(i) + 1], AB::Expr::from(field(hi(*word) as u64)));
    }
}

/// Genesis INC (`q52g`): empty maps, `next_time=0`.
fn eval_bind_genesis_c<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    let mut w = builder.when(cur[COL_Q52G]);
    let words = genesis_inc_tpre_words();
    for (i, word) in words.iter().enumerate() {
        w.assert_eq(cur[tpre_lo(i)], AB::Expr::from(field(lo(*word) as u64)));
        w.assert_eq(cur[tpre_lo(i) + 1], AB::Expr::from(field(hi(*word) as u64)));
    }
}

/// Mid INC (`q52m`, hidx 16): books = mid public; nonce = opening 4/0 `out`;
/// seen = opening 1 `out`. Not Place1 treap algebra; not `F`.
fn eval_bind_mid_inc<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
    pis: &[AB::PublicVar],
) {
    let hidx = cur[COL_HIDX];
    eval_hidx_flag(builder, hidx, cur[COL_IS1], cur[COL_I1INV], HIDX_SEEN_FIRST);
    let is1 = cur[COL_IS1];
    let is1r = cur[COL_IS1R];
    let rootn = cur[COL_ROOTN];
    builder.assert_bool(is1r);
    builder.assert_eq(is1r, is1 * rootn);
    for i in 0..16 {
        builder.assert_zero(is1r * (cur[COL_LAT1 + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_LAT1 + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep = AB::Expr::ONE - nxt[COL_IS1R];
        for i in 0..16 {
            t.assert_zero(keep.clone() * (nxt[COL_LAT1 + i] - cur[COL_LAT1 + i]));
        }
    }
    let nonce_bytes = eval_digest_bytes(
        builder,
        &cur[COL_LAT4..COL_LAT4 + 16],
        &cur[COL_B4..COL_B4 + 256],
    );
    let seen_bytes = eval_digest_bytes(
        builder,
        &cur[COL_LAT1..COL_LAT1 + 16],
        &cur[COL_LAT1B..COL_LAT1B + 256],
    );
    let g38 = eval_pack8(builder, &cur[COL_GAP..COL_GAP + 8]);
    let g41 = eval_pack8(builder, &cur[COL_GAP + 8..COL_GAP + 16]);
    let g49 = eval_pack8(builder, &cur[COL_GAP + 16..COL_GAP + 24]);
    let mut w = builder.when(cur[COL_Q52M]);
    // Nonce root at OFF 121 — same packing as post under q52p.
    w.assert_eq(
        cur[tpre_lo(30)],
        nonce_bytes[0].clone() * AB::Expr::from(field(256)),
    );
    w.assert_eq(
        cur[tpre_lo(30) + 1],
        nonce_bytes[1].clone() + nonce_bytes[2].clone() * AB::Expr::from(field(256)),
    );
    for k in 0..7 {
        let off = 3 + 4 * k;
        let word = 31 + k;
        w.assert_eq(
            cur[tpre_lo(word)],
            nonce_bytes[off].clone() + nonce_bytes[off + 1].clone() * AB::Expr::from(field(256)),
        );
        w.assert_eq(
            cur[tpre_lo(word) + 1],
            nonce_bytes[off + 2].clone()
                + nonce_bytes[off + 3].clone() * AB::Expr::from(field(256)),
        );
    }
    w.assert_eq(
        cur[tpre_lo(38)],
        nonce_bytes[31].clone() + g38 * AB::Expr::from(field(256)),
    );
    w.assert_eq(
        cur[tpre_lo(41) + 1],
        g41 + seen_bytes[0].clone() * AB::Expr::from(field(256)),
    );
    for k in 0..7 {
        let off = 1 + 4 * k;
        let word = 42 + k;
        w.assert_eq(
            cur[tpre_lo(word)],
            seen_bytes[off].clone() + seen_bytes[off + 1].clone() * AB::Expr::from(field(256)),
        );
        w.assert_eq(
            cur[tpre_lo(word) + 1],
            seen_bytes[off + 2].clone() + seen_bytes[off + 3].clone() * AB::Expr::from(field(256)),
        );
    }
    w.assert_eq(
        cur[tpre_lo(49)],
        seen_bytes[29].clone() + seen_bytes[30].clone() * AB::Expr::from(field(256)),
    );
    w.assert_eq(
        cur[tpre_lo(49) + 1],
        seen_bytes[31].clone() + g49 * AB::Expr::from(field(256)),
    );
    // Books = mid public (16 limbs at REST_ROOT_OFF / word 53).
    for i in 0..8 {
        w.assert_eq(cur[tpre_lo(53 + i)], pis[MID_PI_OFF + 2 * i]);
        w.assert_eq(cur[tpre_lo(53 + i) + 1], pis[MID_PI_OFF + 2 * i + 1]);
    }
}

fn eval_bind_map_roots<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    cur: &[AB::Var],
    nxt: &[AB::Var],
) {
    debug_assert_eq!(NONCE_ROOT_OFF, 121);
    debug_assert_eq!(SEEN_ROOT_OFF, 167);
    debug_assert_eq!(REST_ROOT_OFF, 53 * 4);
    let hidx = cur[COL_HIDX];
    eval_hidx_flag(builder, hidx, cur[COL_IS5], cur[COL_I5INV], HIDX_NONCE_ROOT);
    // COL_IS8 flagged in eval_bind_unique_keys (seen root / key-5).
    let is5 = cur[COL_IS5];
    let is8 = cur[COL_IS8];
    let is5r = cur[COL_IS5R];
    let is8r = cur[COL_IS8R];
    let rootn = cur[COL_ROOTN];
    builder.assert_bool(is5r);
    builder.assert_bool(is8r);
    builder.assert_eq(is5r, is5 * rootn);
    builder.assert_eq(is8r, is8 * rootn);
    for i in 0..16 {
        builder.assert_zero(is5r * (cur[COL_LATN + i] - cur[COL_NCVO + i]));
        builder.assert_zero(is8r * (cur[COL_LATS + i] - cur[COL_NCVO + i]));
    }
    {
        let mut first = builder.when_first_row();
        for i in 0..16 {
            first.assert_zero(cur[COL_LATN + i]);
            first.assert_zero(cur[COL_LATS + i]);
        }
    }
    {
        let mut t = builder.when_transition();
        let keep_n = AB::Expr::ONE - nxt[COL_IS5R];
        let keep_s = AB::Expr::ONE - nxt[COL_IS8R];
        for i in 0..16 {
            t.assert_zero(keep_n.clone() * (nxt[COL_LATN + i] - cur[COL_LATN + i]));
            t.assert_zero(keep_s.clone() * (nxt[COL_LATS + i] - cur[COL_LATS + i]));
        }
    }
    let nonce_bytes = eval_digest_bytes(
        builder,
        &cur[COL_LATN..COL_LATN + 16],
        &cur[COL_NBIT..COL_NBIT + 256],
    );
    let seen_bytes = eval_digest_bytes(
        builder,
        &cur[COL_LATS..COL_LATS + 16],
        &cur[COL_SBIT..COL_SBIT + 256],
    );
    let g38 = eval_pack8(builder, &cur[COL_GAP..COL_GAP + 8]);
    let g41 = eval_pack8(builder, &cur[COL_GAP + 8..COL_GAP + 16]);
    let g49 = eval_pack8(builder, &cur[COL_GAP + 16..COL_GAP + 24]);
    let mut w = builder.when(cur[COL_Q52P]);
    w.assert_eq(
        cur[tpre_lo(30)],
        nonce_bytes[0].clone() * AB::Expr::from(field(256)),
    );
    w.assert_eq(
        cur[tpre_lo(30) + 1],
        nonce_bytes[1].clone() + nonce_bytes[2].clone() * AB::Expr::from(field(256)),
    );
    for k in 0..7 {
        let off = 3 + 4 * k;
        let word = 31 + k;
        w.assert_eq(
            cur[tpre_lo(word)],
            nonce_bytes[off].clone() + nonce_bytes[off + 1].clone() * AB::Expr::from(field(256)),
        );
        w.assert_eq(
            cur[tpre_lo(word) + 1],
            nonce_bytes[off + 2].clone()
                + nonce_bytes[off + 3].clone() * AB::Expr::from(field(256)),
        );
    }
    w.assert_eq(
        cur[tpre_lo(38)],
        nonce_bytes[31].clone() + g38 * AB::Expr::from(field(256)),
    );
    w.assert_eq(
        cur[tpre_lo(41) + 1],
        g41 + seen_bytes[0].clone() * AB::Expr::from(field(256)),
    );
    for k in 0..7 {
        let off = 1 + 4 * k;
        let word = 42 + k;
        w.assert_eq(
            cur[tpre_lo(word)],
            seen_bytes[off].clone() + seen_bytes[off + 1].clone() * AB::Expr::from(field(256)),
        );
        w.assert_eq(
            cur[tpre_lo(word) + 1],
            seen_bytes[off + 2].clone() + seen_bytes[off + 3].clone() * AB::Expr::from(field(256)),
        );
    }
    w.assert_eq(
        cur[tpre_lo(49)],
        seen_bytes[29].clone() + seen_bytes[30].clone() * AB::Expr::from(field(256)),
    );
    w.assert_eq(
        cur[tpre_lo(49) + 1],
        seen_bytes[31].clone() + g49 * AB::Expr::from(field(256)),
    );
    let empty = words32(&commitments::treap_empty_digest().0);
    for i in 0..8 {
        w.assert_eq(
            cur[tpre_lo(53 + i)],
            AB::Expr::from(field(lo(empty[i]) as u64)),
        );
        w.assert_eq(
            cur[tpre_lo(53 + i) + 1],
            AB::Expr::from(field(hi(empty[i]) as u64)),
        );
    }
}

/// Post and mid INC (`q52p` / `q52m`): `nonces` / `seenid` / `books` tags and
/// Digest len 32. Mix bytes 153/166/199 are COL_GAP (`s`, 0, `b`). Genesis
/// already dumps all 244 B.
fn eval_bind_inc_map_tags<AB: AirBuilder<F = Val>>(builder: &mut AB, cur: &[AB::Var]) {
    debug_assert_eq!(INC_NONCES_TAG_OFF + INC_NONCES_TAG.len() + 8, NONCE_ROOT_OFF);
    debug_assert_eq!(INC_SEENID_TAG_OFF + INC_SEENID_TAG.len() + 8, SEEN_ROOT_OFF);
    debug_assert_eq!(INC_BOOKS_TAG_OFF + INC_BOOKS_TAG.len() + 8, REST_ROOT_OFF);
    debug_assert_eq!(INC_HEADER_WORDS * 4, INC_NONCES_TAG_OFF + 1);
    let n = INC_NONCES_TAG;
    let s = INC_SEENID_TAG;
    let bks = INC_BOOKS_TAG;
    let dlen = INC_DIGEST_LEN;
    let g38 = eval_pack8(builder, &cur[COL_GAP..COL_GAP + 8]);
    let g41 = eval_pack8(builder, &cur[COL_GAP + 8..COL_GAP + 16]);
    let g49 = eval_pack8(builder, &cur[COL_GAP + 16..COL_GAP + 24]);
    let mut w = builder.when(cur[COL_Q52P] + cur[COL_Q52M]);
    w.assert_eq(
        cur[tpre_lo(27)],
        AB::Expr::from(field(n[1] as u64 | (n[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(27) + 1],
        AB::Expr::from(field(n[3] as u64 | (n[4] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(28)],
        AB::Expr::from(field(n[5] as u64 | dlen << 8)),
    );
    w.assert_zero(cur[tpre_lo(28) + 1]);
    w.assert_zero(cur[tpre_lo(29)]);
    w.assert_zero(cur[tpre_lo(29) + 1]);
    w.assert_eq(g38, AB::Expr::from(field(s[0] as u64)));
    w.assert_eq(
        cur[tpre_lo(38) + 1],
        AB::Expr::from(field(s[1] as u64 | (s[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(39)],
        AB::Expr::from(field(s[3] as u64 | (s[4] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(39) + 1],
        AB::Expr::from(field(s[5] as u64 | dlen << 8)),
    );
    w.assert_zero(cur[tpre_lo(40)]);
    w.assert_zero(cur[tpre_lo(40) + 1]);
    w.assert_zero(cur[tpre_lo(41)]);
    w.assert_zero(g41);
    w.assert_eq(g49, AB::Expr::from(field(bks[0] as u64)));
    w.assert_eq(
        cur[tpre_lo(50)],
        AB::Expr::from(field(bks[1] as u64 | (bks[2] as u64) << 8)),
    );
    w.assert_eq(
        cur[tpre_lo(50) + 1],
        AB::Expr::from(field(bks[3] as u64 | (bks[4] as u64) << 8)),
    );
    w.assert_eq(cur[tpre_lo(51)], AB::Expr::from(field(dlen)));
    w.assert_zero(cur[tpre_lo(51) + 1]);
    w.assert_zero(cur[tpre_lo(52)]);
    w.assert_zero(cur[tpre_lo(52) + 1]);
}

fn generate_height_match_trace(
    preimages: &[Vec<u8>],
    stmt: &tiny_f::MatchStepStatement,
) -> Result<RowMajorMatrix<Val>, ProveError> {
    let h = generate_mixed_openings_trace(preimages, HEIGHT_MATCH_OPENINGS, HM_ROWS, true);
    let m = generate_match_row(stmt).map_err(|_| ProveError::Serialize)?;
    let mut values = vec![Val::ZERO; HM_ROWS * HM_WIDTH];
    let mut lat_n = [Val::ZERO; 16];
    let mut lat_s = [Val::ZERO; 16];
    let mut lat_4 = [Val::ZERO; 16];
    let mut lat_6 = [Val::ZERO; 16];
    let mut lat_1 = [Val::ZERO; 16];
    let mut lat_0 = [Val::ZERO; 16];
    let mut lat_pn1 = [Val::ZERO; 4];
    let mut lat_pn2 = [Val::ZERO; 4];
    let mut lat_po1 = [Val::ZERO; 4];
    let mut lat_po2 = [Val::ZERO; 4];
    let mut heap_sticky = Val::ZERO;
    let mut lat_k4 = Val::ZERO;
    let mut lat_k6 = Val::ZERO;
    let mut lat_tid0 = Val::ZERO;
    let mut lat_town0 = Val::ZERO;
    let mut lat_sid0 = Val::ZERO;
    let mut lat_sown0 = Val::ZERO;
    for r in 0..HM_ROWS {
        let src = &h.values[r * H_WIDTH..(r + 1) * H_WIDTH];
        let dst = &mut values[r * HM_WIDTH..(r + 1) * HM_WIDTH];
        dst[..H_WIDTH].copy_from_slice(src);
        dst[H_WIDTH..H_WIDTH + MATCH_WIDTH].copy_from_slice(&m);
        let hidx = src[COL_HIDX];
        if hidx == field(HIDX_NONCE_ROOT) {
            dst[COL_IS5] = Val::ONE;
            if src[COL_ROOTN] == Val::ONE {
                dst[COL_IS5R] = Val::ONE;
                lat_n.copy_from_slice(&src[COL_NCVO..COL_NCVO + 16]);
            }
        } else {
            dst[COL_I5INV] = (hidx - field(HIDX_NONCE_ROOT)).inverse();
        }
        if hidx == field(HIDX_SEEN_DEMOT) {
            dst[COL_IS7] = Val::ONE;
            if src[COL_ROOTN] == Val::ONE {
                dst[COL_IS7R] = Val::ONE;
                lat_6.copy_from_slice(&src[COL_NCVO..COL_NCVO + 16]);
            }
        } else {
            dst[COL_I7INV] = (hidx - field(HIDX_SEEN_DEMOT)).inverse();
        }
        if hidx == field(HIDX_SEEN_ROOT) {
            dst[COL_IS8] = Val::ONE;
            if src[COL_ROOTN] == Val::ONE {
                dst[COL_IS8R] = Val::ONE;
                lat_s.copy_from_slice(&src[COL_NCVO..COL_NCVO + 16]);
            }
        } else {
            dst[COL_I8INV] = (hidx - field(HIDX_SEEN_ROOT)).inverse();
        }
        if hidx == field(HIDX_NONCE_PREV) {
            dst[COL_IS4] = Val::ONE;
            if src[COL_ROOTN] == Val::ONE {
                dst[COL_IS4R] = Val::ONE;
                lat_4.copy_from_slice(&src[COL_NCVO..COL_NCVO + 16]);
            }
        } else {
            dst[COL_I4INV] = (hidx - field(HIDX_NONCE_PREV)).inverse();
        }
        if hidx == field(HIDX_SEEN_FIRST) {
            dst[COL_IS1] = Val::ONE;
            if src[COL_ROOTN] == Val::ONE {
                dst[COL_IS1R] = Val::ONE;
                lat_1.copy_from_slice(&src[COL_NCVO..COL_NCVO + 16]);
            }
        } else {
            dst[COL_I1INV] = (hidx - field(HIDX_SEEN_FIRST)).inverse();
        }
        if hidx == field(HIDX_NONCE_FIRST) {
            dst[COL_IS0] = Val::ONE;
            if src[COL_ROOTN] == Val::ONE {
                dst[COL_IS0R] = Val::ONE;
                lat_0.copy_from_slice(&src[COL_NCVO..COL_NCVO + 16]);
            }
        } else {
            dst[COL_I0INV] = (hidx - field(HIDX_NONCE_FIRST)).inverse();
        }
        dst[COL_LATN..COL_LATN + 16].copy_from_slice(&lat_n);
        dst[COL_LATS..COL_LATS + 16].copy_from_slice(&lat_s);
        dst[COL_LAT4..COL_LAT4 + 16].copy_from_slice(&lat_4);
        dst[COL_LAT1..COL_LAT1 + 16].copy_from_slice(&lat_1);
        dst[COL_LAT0..COL_LAT0 + 16].copy_from_slice(&lat_0);
        fill_limb_bits(dst, COL_NBIT, &lat_n);
        fill_limb_bits(dst, COL_SBIT, &lat_s);
        fill_limb_bits(dst, COL_B4, &lat_4);
        fill_limb_bits(dst, COL_LAT1B, &lat_1);
        if src[COL_Q52] == Val::ONE {
            fill_tpre_gap_bits(dst, src);
            if src[COL_HLAST] == Val::ONE {
                dst[COL_Q52P] = Val::ONE;
            } else if hidx == field(HIDX_GENESIS_INC) {
                dst[COL_Q52G] = Val::ONE;
            } else if hidx == field(HIDX_MID_INC) {
                dst[COL_Q52M] = Val::ONE;
            }
        }
        if src[COL_BLAST] == Val::ONE && src[COL_NB + 1] == Val::ONE {
            dst[COL_Q51] = Val::ONE;
        }
        if src[COL_BLAST] == Val::ONE && src[COL_NB + 2] == Val::ONE {
            dst[COL_Q11] = Val::ONE;
        }
        if dst[COL_Q51] == Val::ONE && dst[COL_IS8] == Val::ZERO {
            dst[COL_SEEN_RE] = Val::ONE;
        }
        if dst[COL_Q11] == Val::ONE && dst[COL_IS5] == Val::ZERO {
            dst[COL_NONCE_LE] = Val::ONE;
        }
        fill_hidx_is(dst, hidx, COL_IS2, COL_I2INV, HIDX_ORDER_K1);
        fill_hidx_is(dst, hidx, COL_IS3, COL_I3INV, HIDX_NONCE_K2);
        fill_hidx_is(dst, hidx, COL_IS6, COL_I6INV, HIDX_SEEN_K5);
        fill_hidx_is(dst, hidx, COL_IS11, COL_I11INV, HIDX_OWNER_K2);
        fill_hidx_is(dst, hidx, COL_IS12, COL_I12INV, HIDX_ORDER_K5);
        fill_hidx_is(dst, hidx, COL_IS14, COL_I14INV, HIDX_GENESIS_INC);
        fill_hidx_is(dst, hidx, COL_IS15, COL_I15INV, HIDX_MID_INC);
        dst[COL_LAT6..COL_LAT6 + 16].copy_from_slice(&lat_6);
        fill_limb_bits(dst, COL_B6, &lat_6);
        if src[COL_Q24] == Val::ONE && src[COL_ROOTN] == Val::ONE {
            dst[COL_Q24R] = Val::ONE;
        }
        let q33 = src[COL_Q33] == Val::ONE;
        let q49 = src[COL_Q49] == Val::ONE;
        let is11 = dst[COL_IS11] == Val::ONE;
        let is12 = dst[COL_IS12] == Val::ONE;
        let rootn = src[COL_ROOTN] == Val::ONE;
        let prio_limbs = [
            src[COL_NCVO],
            src[COL_NCVO + 1],
            src[COL_NCVO + 2],
            src[COL_NCVO + 3],
        ];
        if q49 && !is11 && rootn {
            dst[COL_LOAD_PN1] = Val::ONE;
            lat_pn1 = prio_limbs;
        }
        if q49 && is11 && rootn {
            dst[COL_LOAD_PN2] = Val::ONE;
            lat_pn2 = prio_limbs;
        }
        if q33 && !is12 && rootn {
            dst[COL_LOAD_PO1] = Val::ONE;
            lat_po1 = prio_limbs;
        }
        if q33 && is12 && rootn {
            dst[COL_LOAD_PO2] = Val::ONE;
            lat_po2 = prio_limbs;
        }
        dst[COL_LAT_PN1..COL_LAT_PN1 + 4].copy_from_slice(&lat_pn1);
        dst[COL_LAT_PN2..COL_LAT_PN2 + 4].copy_from_slice(&lat_pn2);
        dst[COL_LAT_PO1..COL_LAT_PO1 + 4].copy_from_slice(&lat_po1);
        dst[COL_LAT_PO2..COL_LAT_PO2 + 4].copy_from_slice(&lat_po2);
        dst[COL_HEAP_STICKY] = heap_sticky;
        let load = dst[COL_LOAD_PO2] == Val::ONE;
        let rdy = heap_sticky == Val::ONE || load;
        if rdy {
            dst[COL_HEAP_RDY] = Val::ONE;
            fill_u64_limb_gt(
                dst,
                &lat_pn2,
                &lat_pn1,
                COL_HEAP_ND,
                COL_HEAP_NB,
                COL_HEAP_NDB,
            );
            fill_u64_limb_gt(
                dst,
                &lat_po2,
                &lat_po1,
                COL_HEAP_SD,
                COL_HEAP_SB,
                COL_HEAP_SDB,
            );
        }
        heap_sticky = if rdy { Val::ONE } else { Val::ZERO };
        let key_packed = src[tpre_lo(14) + 1].as_canonical_u64();
        if dst[COL_IS4R] == Val::ONE {
            debug_assert_eq!(key_packed % TAKE_PACK, 0);
            lat_k4 = field(key_packed / TAKE_PACK);
        }
        if dst[COL_IS7R] == Val::ONE {
            debug_assert_eq!(key_packed % TAKE_PACK, 0);
            lat_k6 = field(key_packed / TAKE_PACK);
        }
        dst[COL_LAT_K4] = lat_k4;
        dst[COL_LAT_K6] = lat_k6;
        if dst[COL_IS5R] == Val::ONE {
            let key5 = key_packed / TAKE_PACK;
            let k4 = lat_k4.as_canonical_u64();
            debug_assert!(key5 > k4);
            put_u8_bits(dst, COL_BST_ND, key5 - k4 - 1);
        }
        if dst[COL_IS8R] == Val::ONE {
            let key8 = key_packed / TAKE_PACK;
            let k7 = lat_k6.as_canonical_u64();
            debug_assert!(key8 > k7);
            put_u8_bits(dst, COL_BST_SD, key8 - k7 - 1);
        }
        // Insert key latches: Place1/Place2 order+owner prios.
        let is2 = dst[COL_IS2] == Val::ONE;
        let is3 = dst[COL_IS3] == Val::ONE;
        let is6 = dst[COL_IS6] == Val::ONE;
        if is3 && rootn {
            dst[COL_IS3R] = Val::ONE;
        }
        if is6 && rootn {
            dst[COL_IS6R] = Val::ONE;
        }
        let prio_lo = commitments::TREAP_PRIO_DOMAIN[16] as u64;
        let prio_key0 = |src: &[Val]| {
            let w4 = src[tpre_lo(4)].as_canonical_u64();
            debug_assert_eq!(w4 % TAKE_PACK, prio_lo);
            field((w4 - prio_lo) / TAKE_PACK)
        };
        if q33 && is12 && rootn {
            dst[COL_LOAD_TID] = Val::ONE;
            lat_tid0 = prio_key0(src);
        }
        if q49 && is11 && rootn {
            dst[COL_LOAD_TOWN] = Val::ONE;
            lat_town0 = prio_key0(src);
        }
        if q33 && is2 && rootn {
            dst[COL_LOAD_SID] = Val::ONE;
            lat_sid0 = prio_key0(src);
        }
        if q49 && !is11 && rootn {
            dst[COL_LOAD_SOWN] = Val::ONE;
            lat_sown0 = prio_key0(src);
        }
        if q33 && !is2 && !is12 && rootn {
            dst[COL_LOAD_RP] = Val::ONE;
        }
        dst[COL_LAT_TID0] = lat_tid0;
        dst[COL_LAT_TOWN0] = lat_town0;
        dst[COL_LAT_SID0] = lat_sid0;
        dst[COL_LAT_SOWN0] = lat_sown0;
    }
    Ok(RowMajorMatrix::new(values, HM_WIDTH))
}

fn put_u8_bits(row: &mut [Val], col: usize, v: u64) {
    debug_assert!(v < 256);
    for i in 0..8 {
        row[col + i] = field(((v >> i) & 1) as u64);
    }
}

fn limbs_to_u64(limbs: &[Val; 4]) -> u64 {
    let mut v = 0u64;
    for (i, limb) in limbs.iter().enumerate() {
        v |= limb.as_canonical_u64() << (16 * i);
    }
    v
}

fn fill_u64_limb_gt(
    row: &mut [Val],
    a: &[Val; 4],
    b: &[Val; 4],
    diff_col: usize,
    borrow_col: usize,
    bits_col: usize,
) {
    let au = limbs_to_u64(a);
    let bu = limbs_to_u64(b);
    debug_assert!(au > bu);
    let mut tmp = au - bu - 1;
    for i in 0..4 {
        let limb = (tmp & 0xffff) as u64;
        row[diff_col + i] = field(limb);
        for bit in 0..16 {
            row[bits_col + i * 16 + bit] = field(((limb >> bit) & 1) as u64);
        }
        tmp >>= 16;
    }
    // borrows: reconstruct from limb subtraction
    let mut borrow = 1u64; // initial -1
    for i in 0..4 {
        let ai = a[i].as_canonical_u64();
        let bi = b[i].as_canonical_u64();
        let raw = ai as i64 - bi as i64 - borrow as i64;
        if i < 3 {
            if raw < 0 {
                row[borrow_col + i] = Val::ONE;
                borrow = 1;
            } else {
                row[borrow_col + i] = Val::ZERO;
                borrow = 0;
            }
        } else {
            debug_assert!(raw >= 0);
            row[borrow_col + i] = Val::ZERO;
        }
    }
}

fn fill_hidx_is(dst: &mut [Val], hidx: Val, is_col: usize, inv_col: usize, target: u64) {
    if hidx == field(target) {
        dst[is_col] = Val::ONE;
    } else {
        dst[inv_col] = (hidx - field(target)).inverse();
    }
}

fn fill_limb_bits(row: &mut [Val], col: usize, limbs: &[Val]) {
    for (i, limb) in limbs.iter().enumerate() {
        let v = limb.as_canonical_u64();
        let b0 = (v & 0xff) as u8;
        let b1 = ((v >> 8) & 0xff) as u8;
        fill_bits8(row, col + i * 16, b0);
        fill_bits8(row, col + i * 16 + 8, b1);
    }
}

fn fill_bits8(row: &mut [Val], col: usize, byte: u8) {
    for i in 0..8 {
        if byte & (1 << i) != 0 {
            row[col + i] = Val::ONE;
        }
    }
}

fn fill_tpre_gap_bits(row: &mut [Val], src: &[Val]) {
    let b153 = tpre_byte(src, 153);
    let b166 = tpre_byte(src, 166);
    let b199 = tpre_byte(src, 199);
    fill_bits8(row, COL_GAP, b153);
    fill_bits8(row, COL_GAP + 8, b166);
    fill_bits8(row, COL_GAP + 16, b199);
}

fn tpre_byte(src: &[Val], off: usize) -> u8 {
    let word = off / 4;
    let limb = src[tpre_lo(word) + (off % 4) / 2];
    let v = limb.as_canonical_u64() as u16;
    if off % 2 == 0 {
        (v & 0xff) as u8
    } else {
        (v >> 8) as u8
    }
}

/// Digest of the 216 B resting leaf opening. Default mid-books public.
pub fn mid_books_from_openings(preimages: &[Vec<u8>]) -> Option<[u8; 32]> {
    let resting = preimages.iter().find(|p| p.len() == RESTING_NODE_BYTES)?;
    Some(blake3_hash_msg(resting))
}

fn digest_to_pis(digest: &[u8; 32]) -> [Val; 16] {
    let dw = words32(digest);
    let mut pis = [Val::ZERO; 16];
    for i in 0..8 {
        pis[2 * i] = field(lo(dw[i]) as u64);
        pis[2 * i + 1] = field(hi(dw[i]) as u64);
    }
    pis
}

fn public_height_match(
    preimages: &[Vec<u8>],
    stmt: &tiny_f::MatchStepStatement,
    mid_books: &[u8; 32],
) -> Result<[Val; HM_PIS], ProveError> {
    let h = public_engine_tape(preimages);
    let m = match_public_values(stmt).map_err(|_| ProveError::Serialize)?;
    let mid = digest_to_pis(mid_books);
    let mut pis = [Val::ZERO; HM_PIS];
    pis[..T_PIS].copy_from_slice(&h);
    pis[T_PIS..MID_PI_OFF].copy_from_slice(&m);
    pis[MID_PI_OFF..].copy_from_slice(&mid);
    Ok(pis)
}

#[derive(Clone, Debug)]
pub struct HeightMatchProof {
    pub bytes: Vec<u8>,
}

/// Prove with mid-books = resting leaf digest. Pair with explicit mid via
/// [`prove_height_match_mid`] when the mid claim is independent (ApplyWitness).
pub fn prove_height_match_with(
    preimages: Vec<Vec<u8>>,
    stmt: tiny_f::MatchStepStatement,
    class: FriClass,
) -> Result<HeightMatchProof, ProveError> {
    let mid = mid_books_from_openings(&preimages).ok_or(ProveError::Serialize)?;
    prove_height_match_mid(preimages, stmt, mid, class)
}

/// Prove with an explicit mid-apply books root public. AIR requires it equal
/// the 216 B resting leaf digest. Not Place1 algebra; not `F`.
pub fn prove_height_match_mid(
    preimages: Vec<Vec<u8>>,
    stmt: tiny_f::MatchStepStatement,
    mid_books: [u8; 32],
    class: FriClass,
) -> Result<HeightMatchProof, ProveError> {
    let config = make_config(class);
    let trace = generate_height_match_trace(&preimages, &stmt)?;
    let pis = public_height_match(&preimages, &stmt, &mid_books)?;
    let proof = prove(&config, &HeightMatchAir, trace, &pis);
    let bytes = postcard::to_allocvec(&proof).map_err(|_| ProveError::Serialize)?;
    Ok(HeightMatchProof { bytes })
}

pub fn verify_height_match_with(
    preimages: Vec<Vec<u8>>,
    stmt: tiny_f::MatchStepStatement,
    proof: &HeightMatchProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    let mid = mid_books_from_openings(&preimages).ok_or(Plonky3VerifyError::Rejected)?;
    verify_height_match_mid(preimages, stmt, mid, proof, class)
}

pub fn verify_height_match_mid(
    preimages: Vec<Vec<u8>>,
    stmt: tiny_f::MatchStepStatement,
    mid_books: [u8; 32],
    proof: &HeightMatchProof,
    class: FriClass,
) -> Result<(), Plonky3VerifyError> {
    if preimages.len() != HEIGHT_MATCH_OPENINGS {
        return Err(Plonky3VerifyError::Rejected);
    }
    let config = make_config(class);
    let pis = public_height_match(&preimages, &stmt, &mid_books)
        .map_err(|_| Plonky3VerifyError::Rejected)?;
    let parsed = postcard::from_bytes(&proof.bytes).map_err(|_| Plonky3VerifyError::Rejected)?;
    verify(&config, &HeightMatchAir, &parsed, &pis).map_err(|_| Plonky3VerifyError::Rejected)
}

pub fn prove_height_match_and_report_with(
    preimages: Vec<Vec<u8>>,
    stmt: tiny_f::MatchStepStatement,
    class: FriClass,
) -> Result<(HeightMatchProof, ProofReport), ProveError> {
    let t0 = std::time::Instant::now();
    let proof = prove_height_match_with(preimages.clone(), stmt, class)?;
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    verify_height_match_with(preimages, stmt, &proof, class).map_err(|_| ProveError::Serialize)?;
    let verify_ms = t1.elapsed().as_millis();
    let report = ProofReport::for_class(class, prove_ms, verify_ms, proof.bytes.len());
    Ok((proof, report))
}

/// Envelope: `public_statement_id` || preimages || match-step || STARK.
pub fn encode_height_match_pi(
    statement_id: [u8; 32],
    preimages: &[Vec<u8>],
    match_stmt: &tiny_f::MatchStepStatement,
    proof: &HeightMatchProof,
) -> Vec<u8> {
    let m = {
        use protocol_types::CanonicalEncode;
        match_stmt.encode_vec()
    };
    let mut out = Vec::with_capacity(40 + proof.bytes.len() + m.len());
    out.extend_from_slice(&statement_id);
    out.extend_from_slice(&(preimages.len() as u32).to_le_bytes());
    for p in preimages {
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&(m.len() as u32).to_le_bytes());
    out.extend_from_slice(&m);
    out.extend_from_slice(&proof.bytes);
    out
}

pub fn decode_height_match_pi(
    bytes: &[u8],
) -> Option<(
    [u8; 32],
    Vec<Vec<u8>>,
    tiny_f::MatchStepStatement,
    HeightMatchProof,
)> {
    if bytes.len() < 36 {
        return None;
    }
    let mut sid = [0u8; 32];
    sid.copy_from_slice(&bytes[..32]);
    let n = u32::from_le_bytes(bytes[32..36].try_into().ok()?) as usize;
    if n != HEIGHT_MATCH_OPENINGS {
        return None;
    }
    let mut i = 36usize;
    let mut preimages = Vec::with_capacity(n);
    for _ in 0..n {
        if i + 4 > bytes.len() {
            return None;
        }
        let len = u32::from_le_bytes(bytes[i..i + 4].try_into().ok()?) as usize;
        i += 4;
        if i + len > bytes.len() {
            return None;
        }
        preimages.push(bytes[i..i + len].to_vec());
        i += len;
    }
    if i + 4 > bytes.len() {
        return None;
    }
    let mlen = u32::from_le_bytes(bytes[i..i + 4].try_into().ok()?) as usize;
    i += 4;
    if i + mlen > bytes.len() {
        return None;
    }
    let match_stmt = {
        use protocol_types::CanonicalDecode;
        tiny_f::MatchStepStatement::decode_slice(&bytes[i..i + mlen]).ok()?
    };
    i += mlen;
    Some((
        sid,
        preimages,
        match_stmt,
        HeightMatchProof {
            bytes: bytes[i..].to_vec(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash64_locksteps_crate() {
        let block = unit_block();
        let ours = blake3_hash64(block);
        let theirs = *blake3::hash(&block).as_bytes();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn hash64_empty_is_not_this_cell() {
        let empty = blake3::hash(&[]);
        let ours = blake3_hash64([0u8; 64]);
        assert_ne!(&ours, empty.as_bytes());
    }

    #[test]
    fn g_wraps_like_portable() {
        let g = Blake3G {
            a: u32::MAX,
            b: 1,
            c: 0,
            d: 0,
            x: 0,
            y: 0,
        };
        let a1 = g.a.wrapping_add(g.b).wrapping_add(g.x);
        assert_eq!(a1, 0);
        let out = g.apply();
        assert_eq!(out[0], 1u32.rotate_right(12));
    }

    #[test]
    fn g_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &Blake3GAir,
            AirLayout::from_air::<Val>(&Blake3GAir),
        );
        eprintln!("blake3 G AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_g() {
        let (proof, report) = prove_g_and_report_with(unit_g(), FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 blake3-G test: prove {} ms, verify {} ms, {} bytes, FRI {} (gadget start, not C' path)",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_g_prod() {
        let (_, report) = prove_g_and_report_with(unit_g(), FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-G prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (gadget start, not C' path)",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_g_prod_again() {
        let (_, report) = prove_g_and_report_with(unit_g(), FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-G prod run2: prove {} ms, verify {} ms, {} bytes (gadget start, not C' path)",
            report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }

    #[test]
    fn compress_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &Blake3CompressAir,
            AirLayout::from_air::<Val>(&Blake3CompressAir),
        );
        eprintln!("blake3 compress AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_compress() {
        let (proof, report) = prove_compress_and_report_with(unit_block(), FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 blake3-compress test: prove {} ms, verify {} ms, {} bytes, FRI {} (one compression, not C' path)",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_compress_prod() {
        let (_, report) = prove_compress_and_report_with(unit_block(), FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-compress prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (one compression, not C' path)",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_compress_prod_again() {
        let (_, report) = prove_compress_and_report_with(unit_block(), FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-compress prod run2: prove {} ms, verify {} ms, {} bytes (one compression, not C' path)",
            report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }

    #[test]
    fn path20_locksteps_crate() {
        let (leaf, sibs) = unit_blake3_path(BLAKE3_PATH_LEN);
        let mut d = leaf;
        for s in &sibs {
            let mut block = [0u8; 64];
            block[..32].copy_from_slice(&d);
            block[32..].copy_from_slice(s);
            d = *blake3::hash(&block).as_bytes();
        }
        assert_eq!(blake3_path(leaf, &sibs), d);
    }

    #[test]
    fn path_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &Blake3PathAir,
            AirLayout::from_air::<Val>(&Blake3PathAir),
        );
        eprintln!("blake3 path AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_blake3_path() {
        let (leaf, sibs) = unit_blake3_path(BLAKE3_PATH_LEN);
        let (proof, report) =
            prove_blake3_path_and_report_with(leaf, sibs, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 blake3-path n=20 test: prove {} ms, verify {} ms, {} bytes, FRI {} (20 compressions, not C' tape)",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_blake3_path_prod() {
        let (leaf, sibs) = unit_blake3_path(BLAKE3_PATH_LEN);
        let (_, report) = prove_blake3_path_and_report_with(leaf, sibs, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-path n=20 prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (20 compressions, not C' tape)",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_blake3_path_prod_again() {
        let (leaf, sibs) = unit_blake3_path(BLAKE3_PATH_LEN);
        let (_, report) = prove_blake3_path_and_report_with(leaf, sibs, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-path n=20 prod run2: prove {} ms, verify {} ms, {} bytes (20 compressions, not C' tape)",
            report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }

    #[test]
    fn hash_msg_locksteps_crate_and_hash64() {
        let block = unit_block();
        assert_eq!(blake3_hash_msg(&block), blake3_hash64(block));
        assert_eq!(blake3_hash_msg(&block), *blake3::hash(&block).as_bytes());
        let (preimage, _) = unit_resting_node();
        assert_eq!(preimage.len(), RESTING_NODE_BYTES);
        assert_eq!(preimage.len().div_ceil(64), NODE_DIGEST_BLOCKS);
        assert_eq!(
            blake3_hash_msg(&preimage),
            *blake3::hash(&preimage).as_bytes()
        );
    }

    #[test]
    fn node_digest_locksteps_hashed_map() {
        let (key, value) = unit_resting_kv();
        let empty = commitments::treap_empty_digest();
        let preimage = node_preimage(empty.0, &key, &value, empty.0);
        let native = blake3_hash_msg(&preimage);
        assert_eq!(
            native,
            commitments::treap_node_digest(empty, &key, &value, empty).0
        );
        let mut map = commitments::HashedMap::with_hash(commitments::TreapHash::Blake3);
        map.upsert(&key, &value);
        assert_eq!(map.root().0, native);
        let (unit_pre, unit_d) = unit_resting_node();
        assert_eq!(unit_pre, preimage);
        assert_eq!(unit_d, native);
    }

    #[test]
    fn upsert_node_path_is_nineteen_mixed_openings() {
        use commitments::{
            start_node_digest_trace, start_prio_trace, take_node_digest_trace, take_prio_trace,
            take_treap_hash_calls, HashedMap, TreapHash,
        };
        let mut m = HashedMap::with_hash(TreapHash::Blake3Count);
        for i in 0..8_000u128 {
            let (k, v) = unit_resting_kv_at(i);
            m.upsert(&k, &v);
        }
        let _ = take_treap_hash_calls();
        start_node_digest_trace();
        start_prio_trace();
        let (k, v) = unit_resting_kv_at(8_000);
        m.upsert(&k, &v);
        let calls = take_treap_hash_calls();
        assert_eq!(calls.prio, NODE_PATH_PRIO as u64);
        assert_eq!(calls.node, NODE_PATH_NODE_OPENINGS as u64);
        assert_eq!(calls.blake3(), NODE_PATH_LEN as u64);
        assert_eq!(take_node_digest_trace().len(), NODE_PATH_NODE_OPENINGS);
        assert_eq!(take_prio_trace().len(), NODE_PATH_PRIO);

        let preimages = unit_upsert_node_path();
        assert_eq!(preimages.len(), NODE_PATH_LEN);
        assert_eq!(NODE_PATH_LEN, HEIGHT_MATCH_OPENINGS); // count collide; tapes differ
        let mut lens = std::collections::BTreeMap::new();
        let mut blocks = 0usize;
        for p in &preimages {
            *lens.entry(p.len()).or_insert(0usize) += 1;
            blocks += opening_nblocks(p.len());
            assert_eq!(blake3_hash_msg(p), *blake3::hash(p).as_bytes());
        }
        assert_eq!(lens.get(&RESTING_NODE_BYTES), Some(&18));
        assert_eq!(lens.get(&PRIO_ORDER_BYTES), Some(&1));
        // 18×256 + 64 = 4672.
        assert_eq!(blocks * C_ROWS, 4_672);
        eprintln!(
            "upsert at 8k: n={} lens={:?} rows={} (18 resting + 1 prio; count=HeightMatch 19, different tape, not F)",
            preimages.len(),
            lens,
            blocks * C_ROWS
        );
    }

    #[test]
    fn engine_insert_opening_sizes() {
        use clob::testutil::{btree_engine_v1, limit_v1, load_places_v1};
        use protocol_types::{Input, Side};
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        e.apply_all(load_places_v1(8_000));
        let _ = commitments::take_treap_hash_calls();
        commitments::start_node_digest_trace();
        e.apply(Input::Place(limit_v1(8_001, 2, Side::Buy, 1, 50, 1)));
        let calls = commitments::take_treap_hash_calls();
        let openings = commitments::take_node_digest_trace();
        let mut lens = std::collections::BTreeMap::new();
        for o in &openings {
            let n = o.preimage().len();
            *lens.entry(n).or_insert(0usize) += 1;
            assert_eq!(
                blake3_hash_msg(&o.preimage()),
                *blake3::hash(&o.preimage()).as_bytes()
            );
        }
        eprintln!(
            "engine insert at 8k: prio={} node={} blake3={} openings={} lens={:?}",
            calls.prio,
            calls.node,
            calls.blake3(),
            openings.len(),
            lens
        );
        assert_eq!(calls.prio, ENGINE_INSERT_PRIO as u64);
        assert_eq!(calls.node, ENGINE_INSERT_NODE_OPENINGS as u64);
        assert_eq!(calls.blake3(), ENGINE_INSERT_OPENINGS as u64);
        assert_eq!(openings.len(), ENGINE_INSERT_NODE_OPENINGS);
        assert_eq!(lens.get(&SEEN_NODE_BYTES), Some(&33));
        assert_eq!(lens.get(&NONCE_NODE_BYTES), Some(&3));
        assert_eq!(lens.get(&RESTING_NODE_BYTES), Some(&33));
    }

    #[test]
    fn engine_tape8_opening_sizes() {
        use clob::testutil::{btree_engine_v1, churn_tape_v1, load_places_v1};
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        e.apply_all(load_places_v1(8_000));
        let _ = commitments::take_treap_hash_calls();
        commitments::start_node_digest_trace();
        let tape = churn_tape_v1(8_000, 8);
        assert_eq!(tape.len(), ENGINE_TAPE_EVENTS);
        e.apply_all(tape);
        let calls = commitments::take_treap_hash_calls();
        let openings = commitments::take_node_digest_trace();
        let mut lens = std::collections::BTreeMap::new();
        let mut blocks = 0usize;
        for o in &openings {
            let n = o.preimage().len();
            *lens.entry(n).or_insert(0usize) += 1;
            blocks += opening_nblocks(n);
            assert_eq!(
                blake3_hash_msg(&o.preimage()),
                *blake3::hash(&o.preimage()).as_bytes()
            );
        }
        eprintln!(
            "engine tape8 at 8k: prio={} node={} blake3={} openings={} blocks={} rows={} lens={:?}",
            calls.prio,
            calls.node,
            calls.blake3(),
            openings.len(),
            blocks,
            blocks * C_ROWS,
            lens
        );
        assert_eq!(calls.prio, ENGINE_TAPE_PRIO as u64);
        assert_eq!(calls.node, ENGINE_TAPE_NODE_OPENINGS as u64);
        assert_eq!(calls.blake3(), ENGINE_TAPE_OPENINGS as u64);
        assert_eq!(openings.len(), ENGINE_TAPE_NODE_OPENINGS);
        assert_eq!(lens.get(&SEEN_NODE_BYTES), Some(&123));
        assert_eq!(lens.get(&NONCE_NODE_BYTES), Some(&18));
        assert_eq!(lens.get(&RESTING_NODE_BYTES), Some(&128));
        assert_eq!(blocks * C_ROWS, 51_968);
    }

    #[test]
    fn engine_loaded_10k_opening_sizes() {
        use clob::testutil::{btree_engine_v1, churn_tape_v1, load_places_v1};
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        e.apply_all(load_places_v1(8_000));
        let _ = commitments::take_treap_hash_calls();
        commitments::start_node_digest_trace();
        let tape = churn_tape_v1(8_000, 10_000);
        assert_eq!(tape.len(), 10_000);
        e.apply_all(tape);
        let calls = commitments::take_treap_hash_calls();
        let openings = commitments::take_node_digest_trace();
        let mut lens = std::collections::BTreeMap::new();
        let mut blocks = 0usize;
        for o in &openings {
            let n = o.preimage().len();
            *lens.entry(n).or_insert(0usize) += 1;
            blocks += opening_nblocks(n);
        }
        let rows = blocks * C_ROWS;
        let mut pow2 = 1usize;
        while pow2 < rows {
            pow2 *= 2;
        }
        eprintln!(
            "engine loaded 10k at 8k: prio={} node={} blake3={} openings={} blocks={} rows={} pow2={} lens={:?} (not one STARK; 8-event tape was {} openings / {} rows)",
            calls.prio,
            calls.node,
            calls.blake3(),
            openings.len(),
            blocks,
            rows,
            pow2,
            lens,
            ENGINE_TAPE_OPENINGS,
            T_ROWS
        );
        assert_eq!(calls.node, openings.len() as u64);
        assert_eq!(calls.prio, 12_502);
        assert_eq!(calls.node, 363_497);
        assert_eq!(calls.blake3(), 375_999);
        assert_eq!(openings.len(), 363_497);
        assert_eq!(lens.get(&SEEN_NODE_BYTES), Some(&160_851));
        assert_eq!(lens.get(&NONCE_NODE_BYTES), Some(&17_504));
        assert_eq!(lens.get(&RESTING_NODE_BYTES), Some(&185_142));
        assert_eq!(rows, 71_346_048);
        assert_eq!(pow2, 134_217_728);
        assert!(openings.len() > ENGINE_TAPE_OPENINGS * 100);
        assert!(rows > T_ROWS * 100);
        for o in openings.iter().step_by(openings.len() / 16) {
            let p = o.preimage();
            assert_eq!(blake3_hash_msg(&p), *blake3::hash(&p).as_bytes());
        }
    }

    #[test]
    fn resting_kv_locksteps_clob_leaf() {
        use clob::RestingOrder;
        use protocol_types::{
            CanonicalEncode, Height, InstrumentId, OrderId, OwnerId, Price, Qty, Side, TimeSeq,
        };
        let order = RestingOrder {
            id: OrderId::from_u128(1),
            instrument: InstrumentId(1),
            side: Side::Sell,
            remaining: Qty(10),
            price: Price(90),
            owner: OwnerId::from_byte(1),
            expiry: Height(1),
            nonce: 0,
            time: TimeSeq(0),
        };
        let (key, value) = unit_resting_kv();
        assert_eq!(key, order.id.encode_vec());
        assert_eq!(value, order.leaf_bytes());
        assert_eq!(value.len(), 101);
    }

    #[test]
    fn node_digest_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &NodeDigestAir,
            AirLayout::from_air::<Val>(&NodeDigestAir),
        );
        eprintln!("blake3 node_digest AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_node_digest() {
        let (preimage, _) = unit_resting_node();
        let (proof, report) = prove_node_digest_and_report_with(preimage, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 blake3-node_digest test: prove {} ms, verify {} ms, {} bytes, FRI {} (4-block C' string, not path of 20, not 8k tape)",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_node_digest_prod() {
        let (preimage, _) = unit_resting_node();
        let (_, report) = prove_node_digest_and_report_with(preimage, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-node_digest prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (4-block C' string, not 8k tape)",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_node_digest_prod_again() {
        let (preimage, _) = unit_resting_node();
        let (_, report) = prove_node_digest_and_report_with(preimage, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-node_digest prod run2: prove {} ms, verify {} ms, {} bytes (4-block C' string, not 8k tape)",
            report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }

    fn cached_upsert_path() -> Vec<Vec<u8>> {
        static P: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
        P.get_or_init(unit_upsert_node_path).clone()
    }

    #[test]
    fn node_path_openings_are_chronological() {
        let mut m = commitments::HashedMap::with_hash(commitments::TreapHash::Blake3);
        for i in 0..8_000u128 {
            let (k, v) = unit_resting_kv_at(i);
            m.upsert(&k, &v);
        }
        commitments::start_c_prime_trace();
        commitments::start_node_digest_trace();
        commitments::start_prio_trace();
        let (k, v) = unit_resting_kv_at(8_000);
        m.upsert(&k, &v);
        let chrono = commitments::take_c_prime_trace();
        let mut split: Vec<Vec<u8>> = commitments::take_node_digest_trace()
            .into_iter()
            .map(|o| o.preimage())
            .collect();
        split.extend(commitments::take_prio_trace());
        assert_eq!(chrono.len(), NODE_PATH_LEN);
        assert_eq!(split.len(), NODE_PATH_LEN);
        assert_ne!(chrono, split, "chrono order must differ from node||prio");
        let mut a = chrono.clone();
        a.sort();
        let mut b = split.clone();
        b.sort();
        assert_eq!(a, b, "chrono and split are the same multiset");
        assert_eq!(chrono, unit_upsert_node_path());
    }

    #[test]
    fn node_path_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &NodePathAir,
            AirLayout::from_air::<Val>(&NodePathAir),
        );
        eprintln!("blake3 node_path AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_node_path() {
        let preimages = cached_upsert_path();
        let (proof, report) = prove_node_path_and_report_with(preimages, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 blake3-node_path n={} test: prove {} ms, verify {} ms, {} bytes, FRI {} (chrono 18 resting + 1 prio; count=HeightMatch 19, different tape, not F)",
            NODE_PATH_LEN, report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_node_path_prod() {
        let preimages = cached_upsert_path();
        let (_, report) = prove_node_path_and_report_with(preimages, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-node_path n={} prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (chrono 18 resting + 1 prio, not HeightMatch tape, not F)",
            NODE_PATH_LEN,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_node_path_prod_again() {
        let preimages = cached_upsert_path();
        let (_, report) = prove_node_path_and_report_with(preimages, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-node_path n={} prod run2: prove {} ms, verify {} ms, {} bytes (chrono 18 resting + 1 prio, not HeightMatch tape, not F)",
            NODE_PATH_LEN, report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }

    fn unit_book_walk() -> tiny_f::BookStepStatement {
        use protocol_types::{Price, Qty};
        tiny_f::BookStepStatement::prove_native(tiny_f::BookStepInstance {
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
    fn book_node_path_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &BookNodePathAir,
            AirLayout::from_air::<Val>(&BookNodePathAir),
        );
        eprintln!("blake3 book+node_path AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_book_node_path() {
        let preimages = cached_upsert_path();
        let (proof, report) =
            prove_book_node_path_and_report_with(preimages, unit_book_walk(), FriClass::Test)
                .unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 book+node_path test: prove {} ms, verify {} ms, {} bytes, FRI {} (chrono 18 resting + 1 prio + book-step, not HeightMatch, not engine 72, not F)",
            report.prove_ms, report.verify_ms, report.proof_bytes, report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_book_node_path_prod() {
        let preimages = cached_upsert_path();
        let (_, report) =
            prove_book_node_path_and_report_with(preimages, unit_book_walk(), FriClass::Prod)
                .unwrap();
        eprintln!(
            "plonky3 book+node_path prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (chrono 18 resting + 1 prio + book-step, not HeightMatch, not F)",
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_book_node_path_prod_again() {
        let preimages = cached_upsert_path();
        let (_, report) =
            prove_book_node_path_and_report_with(preimages, unit_book_walk(), FriClass::Prod)
                .unwrap();
        eprintln!(
            "plonky3 book+node_path prod run2: prove {} ms, verify {} ms, {} bytes (chrono 18 resting + 1 prio + book-step, not HeightMatch, not F)",
            report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }


    fn unit_engine_insert_openings() -> Vec<Vec<u8>> {
        use clob::testutil::{btree_engine_v1, limit_v1, load_places_v1};
        use protocol_types::{Input, Side};
        let mut e = btree_engine_v1();
        e.apply_all(load_places_v1(8_000));
        commitments::start_c_prime_trace();
        e.apply(Input::Place(limit_v1(8_001, 2, Side::Buy, 1, 50, 1)));
        commitments::take_c_prime_trace()
    }

    fn cached_engine_insert_openings() -> Vec<Vec<u8>> {
        static P: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
        P.get_or_init(unit_engine_insert_openings).clone()
    }

    #[test]
    fn engine_insert_openings_are_mixed_node_digest() {
        let preimages = cached_engine_insert_openings();
        assert_eq!(preimages.len(), ENGINE_INSERT_OPENINGS);
        let mut lens = std::collections::BTreeMap::new();
        let mut blocks = 0usize;
        for p in &preimages {
            *lens.entry(p.len()).or_insert(0usize) += 1;
            blocks += opening_nblocks(p.len());
            assert_eq!(blake3_hash_msg(p), *blake3::hash(p).as_bytes());
        }
        assert_eq!(lens.get(&SEEN_NODE_BYTES), Some(&33));
        assert_eq!(lens.get(&NONCE_NODE_BYTES), Some(&3));
        assert_eq!(lens.get(&RESTING_NODE_BYTES), Some(&33));
        assert_eq!(lens.get(&PRIO_OWNER_BYTES), Some(&1));
        assert_eq!(lens.get(&PRIO_ORDER_BYTES), Some(&2));
        // Chrono starts with owner prio (not node‖prio).
        assert_eq!(preimages[0].len(), PRIO_OWNER_BYTES);
        // 13248 node rows + 3×64 prio = 13440.
        assert_eq!(blocks * C_ROWS, 13_440);
        eprintln!(
            "engine Place C' openings: n={} lens={:?} rows={} (chrono 69 node + 3 prio, not HeightMatch, not F)",
            preimages.len(),
            lens,
            blocks * C_ROWS
        );
    }

    #[test]
    fn engine_insert_openings_are_chronological() {
        use clob::testutil::{btree_engine_v1, limit_v1, load_places_v1};
        use protocol_types::{Input, Side};
        let mut e = btree_engine_v1();
        e.apply_all(load_places_v1(8_000));
        commitments::start_c_prime_trace();
        commitments::start_node_digest_trace();
        commitments::start_prio_trace();
        e.apply(Input::Place(limit_v1(8_001, 2, Side::Buy, 1, 50, 1)));
        let chrono = commitments::take_c_prime_trace();
        let mut split: Vec<Vec<u8>> = commitments::take_node_digest_trace()
            .into_iter()
            .map(|o| o.preimage())
            .collect();
        split.extend(commitments::take_prio_trace());
        assert_eq!(chrono.len(), ENGINE_INSERT_OPENINGS);
        assert_eq!(split.len(), ENGINE_INSERT_OPENINGS);
        assert_ne!(chrono, split, "chrono order must differ from node||prio");
        let mut a = chrono.clone();
        a.sort();
        let mut b = split.clone();
        b.sort();
        assert_eq!(a, b, "chrono and split are the same multiset");
        assert_eq!(chrono[0].len(), PRIO_OWNER_BYTES);
    }

    #[test]
    fn engine_insert_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &EngineInsertAir,
            AirLayout::from_air::<Val>(&EngineInsertAir),
        );
        eprintln!("blake3 engine_insert AIR max constraint degree {d}");
        assert_eq!(d, 3);
    }









    /// Corrupt nonce3 left so it disagrees with latched out(2).
    #[test]
    fn engine_insert_wrong_nonce_left_rejected() {
        let mut preimages = cached_engine_insert_openings();
        preimages[3][RESTING_LEFT_OFF] ^= 1;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_engine_insert_with(preimages.clone(), FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_engine_insert_with(preimages, &proof, FriClass::Test).is_err());
            }
        }
    }

    /// Corrupt seen[7] right so it disagrees with latched out(6).
    #[test]
    fn engine_insert_wrong_seen_sib_right_rejected() {
        let mut preimages = cached_engine_insert_openings();
        preimages[7][SEEN_RIGHT_OFF] ^= 1;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_engine_insert_with(preimages.clone(), FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_engine_insert_with(preimages, &proof, FriClass::Test).is_err());
            }
        }
    }

    /// Corrupt seen[9] left so it disagrees with latched out(8).
    #[test]
    fn engine_insert_wrong_seen_sib_left_rejected() {
        let mut preimages = cached_engine_insert_openings();
        preimages[9][RESTING_LEFT_OFF] ^= 1;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_engine_insert_with(preimages.clone(), FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_engine_insert_with(preimages, &proof, FriClass::Test).is_err());
            }
        }
    }

    /// Corrupt rest[61] right so it disagrees with latched out(58).
    #[test]
    fn engine_insert_wrong_rest_sib_right_rejected() {
        let mut preimages = cached_engine_insert_openings();
        preimages[61][RESTING_RIGHT_OFF] ^= 1;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_engine_insert_with(preimages.clone(), FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_engine_insert_with(preimages, &proof, FriClass::Test).is_err());
            }
        }
    }

    /// Corrupt seen[27] left so it disagrees with latched out(26).
    #[test]
    fn engine_insert_wrong_seen_last_sib_left_rejected() {
        let mut preimages = cached_engine_insert_openings();
        preimages[27][RESTING_LEFT_OFF] ^= 1;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_engine_insert_with(preimages.clone(), FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_engine_insert_with(preimages, &proof, FriClass::Test).is_err());
            }
        }
    }

    /// Constructive: path leaves have empty children; nonce3 left ← out(2);
    /// sib fan-outs right←out(6/40/12/46/20/54/24/58), left←…/18/52/22/56/26/60.
    #[test]
    fn engine_insert_empty_children() {
        let o = cached_engine_insert_openings();
        let empty = commitments::treap_empty_digest().0;
        for &i in &[EI_SEEN_OID_PATH[0], EI_SEEN_OID_PATH[1]] {
            assert_eq!(&o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &empty);
        }
        assert_eq!(
            &o[EI_SEEN_OID_PATH[0]][SEEN_RIGHT_OFF..SEEN_RIGHT_OFF + 32],
            &empty
        );
        for &i in &[EI_REST_OID_PATH[0], EI_REST_OID_PATH[1]] {
            assert_eq!(&o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &empty);
        }
        assert_eq!(
            &o[EI_REST_OID_PATH[0]][RESTING_RIGHT_OFF..RESTING_RIGHT_OFF + 32],
            &empty
        );
        for &i in &[1usize, 2] {
            assert_eq!(&o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &empty);
            assert_eq!(&o[i][NONCE_RIGHT_OFF..NONCE_RIGHT_OFF + 32], &empty);
        }
        assert_eq!(&o[3][NONCE_RIGHT_OFF..NONCE_RIGHT_OFF + 32], &empty);
        assert_eq!(
            &o[3][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
            &blake3_hash_msg(&o[2])
        );
        let s6 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB0]);
        for &i in &EI_SEEN_RIGHT_FROM_SIB0 {
            assert_eq!(&o[i][SEEN_RIGHT_OFF..SEEN_RIGHT_OFF + 32], &s6, "seen {i}");
        }
        let r40 = blake3_hash_msg(&o[EI_HIDX_REST_SIB0]);
        for &i in &EI_REST_RIGHT_FROM_SIB0 {
            assert_eq!(
                &o[i][RESTING_RIGHT_OFF..RESTING_RIGHT_OFF + 32],
                &r40,
                "rest {i}"
            );
        }
        let s8 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB1]);
        for &i in &EI_SEEN_LEFT_FROM_SIB1 {
            assert_eq!(&o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &s8, "seen {i}");
        }
        let r42 = blake3_hash_msg(&o[EI_HIDX_REST_SIB1]);
        for &i in &EI_REST_LEFT_FROM_SIB1 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &r42,
                "rest {i}"
            );
        }
        let s10 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB2]);
        for &i in &EI_SEEN_LEFT_FROM_SIB2 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &s10,
                "seen {i}"
            );
        }
        let r44 = blake3_hash_msg(&o[EI_HIDX_REST_SIB2]);
        for &i in &EI_REST_LEFT_FROM_SIB2 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &r44,
                "rest {i}"
            );
        }
        let s12 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB3]);
        for &i in &EI_SEEN_RIGHT_FROM_SIB3 {
            assert_eq!(&o[i][SEEN_RIGHT_OFF..SEEN_RIGHT_OFF + 32], &s12, "seen {i}");
        }
        let r46 = blake3_hash_msg(&o[EI_HIDX_REST_SIB3]);
        for &i in &EI_REST_RIGHT_FROM_SIB3 {
            assert_eq!(
                &o[i][RESTING_RIGHT_OFF..RESTING_RIGHT_OFF + 32],
                &r46,
                "rest {i}"
            );
        }
        let s14 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB4]);
        for &i in &EI_SEEN_LEFT_FROM_SIB4 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &s14,
                "seen {i}"
            );
        }
        let r48 = blake3_hash_msg(&o[EI_HIDX_REST_SIB4]);
        for &i in &EI_REST_LEFT_FROM_SIB4 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &r48,
                "rest {i}"
            );
        }
        let s16 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB5]);
        for &i in &EI_SEEN_LEFT_FROM_SIB5 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &s16,
                "seen {i}"
            );
        }
        let r50 = blake3_hash_msg(&o[EI_HIDX_REST_SIB5]);
        for &i in &EI_REST_LEFT_FROM_SIB5 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &r50,
                "rest {i}"
            );
        }
        let s18 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB6]);
        for &i in &EI_SEEN_LEFT_FROM_SIB6 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &s18,
                "seen {i}"
            );
        }
        let r52 = blake3_hash_msg(&o[EI_HIDX_REST_SIB6]);
        for &i in &EI_REST_LEFT_FROM_SIB6 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &r52,
                "rest {i}"
            );
        }
        let s20 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB7]);
        for &i in &EI_SEEN_RIGHT_FROM_SIB7 {
            assert_eq!(&o[i][SEEN_RIGHT_OFF..SEEN_RIGHT_OFF + 32], &s20, "seen {i}");
        }
        let r54 = blake3_hash_msg(&o[EI_HIDX_REST_SIB7]);
        for &i in &EI_REST_RIGHT_FROM_SIB7 {
            assert_eq!(
                &o[i][RESTING_RIGHT_OFF..RESTING_RIGHT_OFF + 32],
                &r54,
                "rest {i}"
            );
        }
        let s22 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB8]);
        for &i in &EI_SEEN_LEFT_FROM_SIB8 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &s22,
                "seen {i}"
            );
        }
        let r56 = blake3_hash_msg(&o[EI_HIDX_REST_SIB8]);
        for &i in &EI_REST_LEFT_FROM_SIB8 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &r56,
                "rest {i}"
            );
        }
        let s24 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB9]);
        for &i in &EI_SEEN_RIGHT_FROM_SIB9 {
            assert_eq!(&o[i][SEEN_RIGHT_OFF..SEEN_RIGHT_OFF + 32], &s24, "seen {i}");
        }
        let r58 = blake3_hash_msg(&o[EI_HIDX_REST_SIB9]);
        for &i in &EI_REST_RIGHT_FROM_SIB9 {
            assert_eq!(
                &o[i][RESTING_RIGHT_OFF..RESTING_RIGHT_OFF + 32],
                &r58,
                "rest {i}"
            );
        }
        let s26 = blake3_hash_msg(&o[EI_HIDX_SEEN_SIB10]);
        for &i in &EI_SEEN_LEFT_FROM_SIB10 {
            assert_eq!(&o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &s26, "seen {i}");
        }
        let r60 = blake3_hash_msg(&o[EI_HIDX_REST_SIB10]);
        for &i in &EI_REST_LEFT_FROM_SIB10 {
            assert_eq!(
                &o[i][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32],
                &r60,
                "rest {i}"
            );
        }
    }



    /// Constructive: EngineInsert order/owner prio keys → path seen/rest/nonce.
    #[test]
    fn engine_insert_keys_from_prio() {
        let o = cached_engine_insert_openings();
        let oid = &o[4][17..21];
        assert_eq!(oid, &o[38][17..21]);
        for &i in &EI_SEEN_OID_PATH {
            assert_eq!(oid, &o[i][RESTING_KEY_OFF..RESTING_KEY_OFF + 4], "seen {i}");
        }
        for &i in &EI_REST_OID_PATH {
            assert_eq!(oid, &o[i][RESTING_ID_OFF..RESTING_ID_OFF + 4], "rest {i}");
        }
        assert_eq!(o[0][17], o[1][RESTING_KEY_OFF]);
        assert_eq!(o[0][17], o[3][RESTING_KEY_OFF]);
        for &i in &EI_REST_OID_PATH {
            assert_eq!(o[0][17], o[i][RESTING_OWNER_OFF], "rest owner {i}");
        }
        assert_ne!(o[4][18], 0, "fixture OrderId byte1 nonzero");
        assert_eq!(EI_SEEN_OID_PATH.len(), 12);
        assert_eq!(EI_REST_OID_PATH.len(), 12);
        assert_eq!(ENGINE_INSERT_OPENINGS, 72);
        assert_ne!(ENGINE_INSERT_OPENINGS, HEIGHT_MATCH_OPENINGS);
    }

    /// Corrupt seen leaf key so it disagrees with latched order prio.
    #[test]
    fn engine_insert_wrong_seen_key_rejected() {
        let mut preimages = cached_engine_insert_openings();
        preimages[5][RESTING_KEY_OFF] ^= 1;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_engine_insert_with(preimages.clone(), FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_engine_insert_with(preimages, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn prove_engine_insert() {
        let preimages = cached_engine_insert_openings();
        let (proof, report) =
            prove_engine_insert_and_report_with(preimages, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 blake3-engine_insert n={} test: prove {} ms, verify {} ms, {} bytes, FRI {} (chrono 69 node + 3 prio + insert key latches = 72 C' hashes, not HeightMatch, not F, not 8k tape)",
            ENGINE_INSERT_OPENINGS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_engine_insert_prod() {
        let preimages = cached_engine_insert_openings();
        let (_, report) = prove_engine_insert_and_report_with(preimages, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-engine_insert n={} prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (chrono 69 node + 3 prio + insert keys + empty leaves + nonce 3←2 + sib 6/40/8/42/10/44/12/46/14/48/16/50/18/52/20/54/22/56/24/58/26/60, not HeightMatch, not F)",
            ENGINE_INSERT_OPENINGS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_engine_insert_prod_again() {
        let preimages = cached_engine_insert_openings();
        let (_, report) = prove_engine_insert_and_report_with(preimages, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-engine_insert n={} prod run2: prove {} ms, verify {} ms, {} bytes (chrono 69 node + 3 prio + insert keys + empty leaves + nonce 3←2 + sib 6/40/8/42/10/44/12/46/14/48/16/50/18/52/20/54/22/56/24/58/26/60, not HeightMatch, not F)",
            ENGINE_INSERT_OPENINGS, report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }

    fn unit_engine_tape_openings() -> Vec<Vec<u8>> {
        use clob::testutil::{btree_engine_v1, churn_tape_v1, load_places_v1};
        let mut e = btree_engine_v1();
        e.apply_all(load_places_v1(8_000));
        commitments::start_c_prime_trace();
        e.apply_all(churn_tape_v1(8_000, ENGINE_TAPE_EVENTS));
        commitments::take_c_prime_trace()
    }

    fn cached_engine_tape_openings() -> Vec<Vec<u8>> {
        static P: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
        P.get_or_init(unit_engine_tape_openings).clone()
    }

    #[test]
    fn engine_tape_openings_are_mixed_node_and_prio() {
        let preimages = cached_engine_tape_openings();
        assert_eq!(preimages.len(), ENGINE_TAPE_OPENINGS);
        let mut lens = std::collections::BTreeMap::new();
        let mut blocks = 0usize;
        for p in &preimages {
            *lens.entry(p.len()).or_insert(0usize) += 1;
            blocks += opening_nblocks(p.len());
            assert_eq!(blake3_hash_msg(p), *blake3::hash(p).as_bytes());
        }
        assert_eq!(lens.get(&SEEN_NODE_BYTES), Some(&123));
        assert_eq!(lens.get(&NONCE_NODE_BYTES), Some(&18));
        assert_eq!(lens.get(&RESTING_NODE_BYTES), Some(&128));
        assert_eq!(
            lens.get(&PRIO_ORDER_BYTES).copied().unwrap_or(0)
                + lens.get(&PRIO_OWNER_BYTES).copied().unwrap_or(0),
            ENGINE_TAPE_PRIO
        );
        // Chrono starts with a prio (not node‖prio).
        assert!(
            preimages[0].len() == PRIO_OWNER_BYTES || preimages[0].len() == PRIO_ORDER_BYTES
        );
        // 51968 node rows + 12×64 prio = 52736.
        assert_eq!(blocks * C_ROWS, 52_736);
        eprintln!(
            "engine tape8 C' openings: n={} lens={:?} rows={} (chrono 269 node + 12 prio, not HeightMatch, not F)",
            preimages.len(),
            lens,
            blocks * C_ROWS
        );
    }

    #[test]
    fn engine_tape_openings_are_chronological() {
        use clob::testutil::{btree_engine_v1, churn_tape_v1, load_places_v1};
        let mut e = btree_engine_v1();
        e.apply_all(load_places_v1(8_000));
        commitments::start_c_prime_trace();
        commitments::start_node_digest_trace();
        commitments::start_prio_trace();
        e.apply_all(churn_tape_v1(8_000, ENGINE_TAPE_EVENTS));
        let chrono = commitments::take_c_prime_trace();
        let mut split: Vec<Vec<u8>> = commitments::take_node_digest_trace()
            .into_iter()
            .map(|o| o.preimage())
            .collect();
        split.extend(commitments::take_prio_trace());
        assert_eq!(chrono.len(), ENGINE_TAPE_OPENINGS);
        assert_eq!(split.len(), ENGINE_TAPE_OPENINGS);
        assert_ne!(chrono, split, "chrono order must differ from node||prio");
        let mut a = chrono.clone();
        a.sort();
        let mut b = split.clone();
        b.sort();
        assert_eq!(a, b, "chrono and split are the same multiset");
    }

    #[test]
    fn engine_tape_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &EngineTapeAir,
            AirLayout::from_air::<Val>(&EngineTapeAir),
        );
        eprintln!("blake3 engine_tape AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_engine_tape() {
        let preimages = cached_engine_tape_openings();
        let (proof, report) = prove_engine_tape_and_report_with(preimages, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 blake3-engine_tape n={} events={} test: prove {} ms, verify {} ms, {} bytes, FRI {} (chrono 269 node + 12 prio = 281 C' hashes, not HeightMatch, not Place, not 10k F)",
            ENGINE_TAPE_OPENINGS,
            ENGINE_TAPE_EVENTS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_engine_tape_prod() {
        let preimages = cached_engine_tape_openings();
        let (_, report) = prove_engine_tape_and_report_with(preimages, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-engine_tape n={} events={} prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (chrono 269 node + 12 prio, not HeightMatch, not F)",
            ENGINE_TAPE_OPENINGS,
            ENGINE_TAPE_EVENTS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_engine_tape_prod_again() {
        let preimages = cached_engine_tape_openings();
        let (_, report) = prove_engine_tape_and_report_with(preimages, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 blake3-engine_tape n={} events={} prod run2: prove {} ms, verify {} ms, {} bytes (chrono 269 node + 12 prio, not HeightMatch, not F)",
            ENGINE_TAPE_OPENINGS,
            ENGINE_TAPE_EVENTS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes
        );
    }

    fn unit_height_openings() -> (Vec<Vec<u8>>, [u8; 32], Vec<u8>) {
        use clob::testutil::btree_engine_v1;
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let _ = commitments::take_treap_hash_calls();
        commitments::start_c_prime_trace();
        e.apply_all(crossing_inputs());
        let post = e.state_root().0;
        let inc = e.incremental_root_preimage();
        let openings = commitments::take_c_prime_trace();
        (openings, post, inc)
    }

    fn cached_height_openings() -> Vec<Vec<u8>> {
        static P: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
        P.get_or_init(|| unit_height_openings().0).clone()
    }

    fn crossing_inputs() -> Vec<protocol_types::Input> {
        use clob::testutil::limit_v1;
        use protocol_types::{Input, Side};
        vec![
            Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit_v1(5, 2, Side::Buy, 10, 100, 1)),
        ]
    }

    fn fixture_mid_inc_preimage() -> Vec<u8> {
        use clob::testutil::btree_engine_v1;
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let inputs = crossing_inputs();
        let _ = e.apply_all(std::iter::once(inputs[0].clone()));
        e.incremental_root_preimage()
    }

    fn cached_height_match_openings() -> Vec<Vec<u8>> {
        static P: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
        P.get_or_init(|| {
            let (mut o, post, inc) = unit_height_openings();
            let mid = fixture_mid_inc_preimage();
            o.push(input_commit_preimage(&crossing_inputs()));
            o.push(genesis_inc_preimage());
            o.push(mid.clone());
            o.push(fixture_settlement_preimage());
            o.push(inc);
            assert_eq!(o.len(), HEIGHT_MATCH_OPENINGS);
            assert_eq!(blake3_hash_msg(o.last().unwrap()), post);
            assert_eq!(o[o.len() - 2].len(), SETTLEMENT_COMMIT_BYTES);
            assert_eq!(o[o.len() - 3].len(), INC_ROOT_BYTES); // mid
            assert_eq!(o[o.len() - 4].len(), INC_ROOT_BYTES); // genesis
            assert_eq!(
                &mid[REST_ROOT_OFF..REST_ROOT_OFF + 32],
                &blake3_hash_msg(&o[HIDX_REST as usize])
            );
            o
        })
        .clone()
    }

    fn fixture_settlement_preimage() -> Vec<u8> {
        use clob::testutil::btree_engine_v1;
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let deltas: Vec<_> = e
            .apply_all(crossing_inputs())
            .into_iter()
            .flat_map(|r| r.settlement)
            .collect();
        settlement_commit_preimage(&deltas)
    }

    #[test]
    fn height_openings_are_chronological() {
        use clob::testutil::btree_engine_v1;
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let _ = commitments::take_treap_hash_calls();
        commitments::start_c_prime_trace();
        commitments::start_node_digest_trace();
        commitments::start_prio_trace();
        e.apply_all(crossing_inputs());
        let calls = commitments::take_treap_hash_calls();
        let chrono = commitments::take_c_prime_trace();
        let nodes = commitments::take_node_digest_trace();
        let prios = commitments::take_prio_trace();
        let mut split: Vec<Vec<u8>> = nodes.iter().map(|o| o.preimage()).collect();
        split.extend(prios.iter().cloned());
        eprintln!(
            "chrono probe: blake3={} chrono={} split={} (node={} prio={})",
            calls.blake3(),
            chrono.len(),
            split.len(),
            nodes.len(),
            prios.len()
        );
        for (i, p) in chrono.iter().enumerate() {
            let kind = match p.len() {
                PRIO_ORDER_BYTES => "prio33",
                PRIO_OWNER_BYTES => "prio49",
                SEEN_NODE_BYTES => "seen",
                NONCE_NODE_BYTES => "nonce",
                RESTING_NODE_BYTES => "rest",
                _ => "other",
            };
            eprintln!("  chrono[{i}] len={} kind={kind}", p.len());
        }
        assert_eq!(chrono.len(), HEIGHT_OPENINGS);
        assert_eq!(split.len(), HEIGHT_OPENINGS);
        assert_ne!(chrono, split, "chrono order must differ from node||prio");
        // Map old node||prio indices → chrono.
        let roles = [
            ("NONCE_FIRST", HIDX_NONCE_FIRST as usize),
            ("SEEN_FIRST", HIDX_SEEN_FIRST as usize),
            ("NONCE_K2", HIDX_NONCE_K2 as usize),
            ("NONCE_PREV", HIDX_NONCE_PREV as usize),
            ("NONCE_ROOT", HIDX_NONCE_ROOT as usize),
            ("SEEN_K5", HIDX_SEEN_K5 as usize),
            ("SEEN_DEMOT", HIDX_SEEN_DEMOT as usize),
            ("SEEN_ROOT", HIDX_SEEN_ROOT as usize),
            ("OWNER_K2", HIDX_OWNER_K2 as usize),
            ("ORDER_K5", HIDX_ORDER_K5 as usize),
        ];
        for (name, old) in roles {
            let pre = &split[old];
            let hits: Vec<usize> = chrono
                .iter()
                .enumerate()
                .filter(|(_, p)| *p == pre)
                .map(|(i, _)| i)
                .collect();
            eprintln!(
                "  remap {name}: old={old} chrono_hits={hits:?} (len={})",
                pre.len()
            );
        }
        // Also: which old indices share identical preimages?
        for i in 0..split.len() {
            for j in i + 1..split.len() {
                if split[i] == split[j] {
                    eprintln!("  split dup: {i} ≡ {j} (len={})", split[i].len());
                }
            }
        }
    }

    #[test]
    fn height_opening_sizes() {
        use clob::testutil::{btree_engine_v1, limit_v1};
        use protocol_types::{Input, Side};
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let inputs = vec![
            Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit_v1(5, 2, Side::Buy, 10, 100, 1)),
        ];
        let _ = commitments::take_treap_hash_calls();
        commitments::start_node_digest_trace();
        commitments::start_prio_trace();
        e.apply_all(inputs);
        let post = e.state_root().0;
        let calls = commitments::take_treap_hash_calls();
        let mut preimages: Vec<Vec<u8>> = commitments::take_node_digest_trace()
            .into_iter()
            .map(|o| o.preimage())
            .collect();
        let prio = commitments::take_prio_trace();
        preimages.extend(prio.iter().cloned());
        let mut lens = std::collections::BTreeMap::new();
        let mut blocks = 0usize;
        for p in &preimages {
            *lens.entry(p.len()).or_insert(0usize) += 1;
            blocks += opening_nblocks(p.len());
            assert_eq!(blake3_hash_msg(p), *blake3::hash(p).as_bytes());
        }
        let last = blake3_hash_msg(preimages.last().expect("openings"));
        eprintln!(
            "height-statement C' hashes: prio={} node={} openings={} blocks={} rows={} lens={:?} last!=post_root={}",
            calls.prio,
            calls.node,
            preimages.len(),
            blocks,
            blocks * C_ROWS,
            lens,
            last != post
        );
        assert_eq!(calls.prio, HEIGHT_PRIO as u64);
        assert_eq!(calls.node, HEIGHT_NODE_OPENINGS as u64);
        assert_eq!(prio.len(), HEIGHT_PRIO);
        assert_eq!(preimages.len(), HEIGHT_OPENINGS);
        assert!(blocks * C_ROWS < HO_ROWS);
        assert_ne!(last, post);
        assert_eq!(lens.get(&SEEN_NODE_BYTES), Some(&4));
        assert_eq!(lens.get(&NONCE_NODE_BYTES), Some(&4));
        assert_eq!(lens.get(&RESTING_NODE_BYTES), Some(&1));
        assert_eq!(lens.get(&PRIO_ORDER_BYTES), Some(&3));
        assert_eq!(lens.get(&PRIO_OWNER_BYTES), Some(&2));
        assert_eq!(blocks * C_ROWS, 1856);
    }

    #[test]
    fn height_inc_map_roots_vs_node_openings() {
        use clob::testutil::{btree_engine_v1, limit_v1};
        use protocol_types::{Input, Side};
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let inputs = vec![
            Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit_v1(5, 2, Side::Buy, 10, 100, 1)),
        ];
        commitments::start_node_digest_trace();
        e.apply_all(inputs);
        let openings = commitments::take_node_digest_trace();
        let pre = e.incremental_root_preimage();
        let (nonce_r, seen_r, rest_r) = e.incremental_map_roots();
        let empty = commitments::treap_empty_digest();
        assert_eq!(e.incremental_resting_len(), 0);
        assert_eq!(rest_r, empty);
        assert_eq!(openings[5].out, nonce_r);
        assert_eq!(openings[8].out, seen_r);
        assert_eq!(openings[5].preimage().len(), NONCE_NODE_BYTES);
        assert_eq!(openings[8].preimage().len(), SEEN_NODE_BYTES);
        assert_eq!(&pre[NONCE_ROOT_OFF..NONCE_ROOT_OFF + 32], &nonce_r.0);
        assert_eq!(&pre[SEEN_ROOT_OFF..SEEN_ROOT_OFF + 32], &seen_r.0);
        assert_eq!(&pre[REST_ROOT_OFF..REST_ROOT_OFF + 32], &empty.0);
        assert_ne!(openings[2].out, rest_r);
        assert_eq!(openings[2].preimage().len(), RESTING_NODE_BYTES);
    }

    #[test]
    fn height_seen_nonce_prio_headers() {
        let o = cached_height_match_openings();
        let domain = commitments::TREAP_NODE_DOMAIN;
        let prio_d = commitments::TREAP_PRIO_DOMAIN;
        let mut seen = 0usize;
        let mut nonce = 0usize;
        let mut order_p = 0usize;
        let mut owner_p = 0usize;
        for p in &o {
            if p.len() == SEEN_NODE_BYTES {
                assert_eq!(&p[..17], domain);
                assert_eq!(
                    u16::from_le_bytes(p[17..19].try_into().unwrap()),
                    protocol_types::ENCODING_VERSION
                );
                assert_eq!(u64::from_le_bytes(p[51..59].try_into().unwrap()), RESTING_KEY_LEN);
                assert_eq!(u64::from_le_bytes(p[75..83].try_into().unwrap()), SEEN_VALUE_LEN);
                assert!(p[60..75].iter().all(|x| *x == 0));
                seen += 1;
            }
            if p.len() == NONCE_NODE_BYTES {
                assert_eq!(&p[..17], domain);
                assert_eq!(
                    u16::from_le_bytes(p[17..19].try_into().unwrap()),
                    protocol_types::ENCODING_VERSION
                );
                assert_eq!(u64::from_le_bytes(p[51..59].try_into().unwrap()), NONCE_KEY_LEN);
                assert_eq!(u64::from_le_bytes(p[91..99].try_into().unwrap()), NONCE_VALUE_LEN);
                assert!(p[60..91].iter().all(|x| *x == 0));
                assert_eq!(
                    u64::from_le_bytes(p[NONCE_VALUE_OFF..NONCE_VALUE_OFF + 8].try_into().unwrap()),
                    ORDER_NONCE
                );
                nonce += 1;
            }
            if p.len() == PRIO_ORDER_BYTES {
                assert_eq!(&p[..17], prio_d);
                assert!(p[18..].iter().all(|x| *x == 0));
                order_p += 1;
            }
            if p.len() == PRIO_OWNER_BYTES {
                assert_eq!(&p[..17], prio_d);
                assert!(p[18..].iter().all(|x| *x == 0));
                owner_p += 1;
            }
        }
        assert_eq!(seen, 4);
        assert_eq!(nonce, 4);
        assert_eq!(order_p, 3);
        assert_eq!(owner_p, 2);
        let empty = commitments::treap_empty_digest().0;
        let want: [(usize, bool, bool); 8] = [
            (HIDX_NONCE_FIRST as usize, true, true),
            (HIDX_SEEN_FIRST as usize, true, true),
            (HIDX_NONCE_K2 as usize, true, true),
            (HIDX_NONCE_PREV as usize, true, true),
            (HIDX_NONCE_ROOT as usize, false, true),
            (HIDX_SEEN_K5 as usize, true, true),
            (HIDX_SEEN_DEMOT as usize, true, true),
            (HIDX_SEEN_ROOT as usize, false, true),
        ];
        for &(h, left_e, right_e) in &want {
            let p = &o[h];
            let (left, right) = match p.len() {
                SEEN_NODE_BYTES => {
                    assert_eq!(SEEN_RIGHT_OFF, 83);
                    (&p[RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &p[SEEN_RIGHT_OFF..SEEN_RIGHT_OFF + 32])
                }
                NONCE_NODE_BYTES => {
                    (&p[RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &p[NONCE_RIGHT_OFF..NONCE_RIGHT_OFF + 32])
                }
                _ => panic!("hidx {h}"),
            };
            assert_eq!(left == empty, left_e, "hidx={h} left");
            assert_eq!(right == empty, right_e, "hidx={h} right");
        }
        let nr = HIDX_NONCE_ROOT as usize;
        let sr = HIDX_SEEN_ROOT as usize;
        let np = HIDX_NONCE_PREV as usize;
        let sd = HIDX_SEEN_DEMOT as usize;
        let nf = HIDX_NONCE_FIRST as usize;
        let sf = HIDX_SEEN_FIRST as usize;
        assert_ne!(&o[nr][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &empty);
        assert_ne!(&o[sr][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &empty);
        let d_nf = blake3_hash_msg(&o[nf]);
        let d_sf = blake3_hash_msg(&o[sf]);
        let d_np = blake3_hash_msg(&o[np]);
        let d_sd = blake3_hash_msg(&o[sd]);
        assert_eq!(d_nf, d_np);
        assert_eq!(d_sf, d_sd);
        assert_eq!(&o[nr][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &d_np);
        assert_eq!(&o[sr][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &d_sd);
        assert_eq!(HIDX_NONCE_PREV, 8);
        assert_eq!(HIDX_SEEN_K5, 11);
        assert_eq!(HIDX_SEEN_DEMOT, 12);
        assert_eq!(HIDX_SEEN_ROOT, 13);
        assert_eq!(o[nf], o[np]);
        assert_eq!(o[sf], o[sd]);
        let outs: Vec<[u8; 32]> = (0..14).map(|h| blake3_hash_msg(&o[h])).collect();
        let mut edges = Vec::new();
        for parent in 0..14 {
            let p = &o[parent];
            let (left, right) = match p.len() {
                SEEN_NODE_BYTES => (&p[19..51], &p[83..115]),
                NONCE_NODE_BYTES => (&p[19..51], &p[107..139]),
                RESTING_NODE_BYTES => (&p[19..51], &p[184..216]),
                _ => continue,
            };
            for child in 0..14 {
                if child == parent {
                    continue;
                }
                if left == &outs[child] {
                    edges.push((parent, "left", child));
                }
                if right == &outs[child] {
                    edges.push((parent, "right", child));
                }
            }
        }
        assert_eq!(
            edges,
            vec![
                (HIDX_NONCE_ROOT as usize, "left", HIDX_NONCE_FIRST as usize),
                (HIDX_NONCE_ROOT as usize, "left", HIDX_NONCE_PREV as usize),
                (HIDX_SEEN_ROOT as usize, "left", HIDX_SEEN_FIRST as usize),
                (HIDX_SEEN_ROOT as usize, "left", HIDX_SEEN_DEMOT as usize),
            ]
        );
        let mut dup_pairs = Vec::new();
        for a in 0..14 {
            for b in (a + 1)..14 {
                if outs[a] == outs[b] {
                    dup_pairs.push((a, b));
                }
            }
        }
        assert_eq!(
            dup_pairs,
            vec![
                (HIDX_NONCE_FIRST as usize, HIDX_NONCE_PREV as usize),
                (2, 4), // duplicate OrderId=1 prio calls
                (HIDX_SEEN_FIRST as usize, HIDX_SEEN_DEMOT as usize),
            ]
        );
    }

    #[test]
    fn height_opening_key0_by_hidx() {
        let o = cached_height_match_openings();
        // Chronological map (skip resting hidx 5).
        const WANT: [(usize, u8); 13] = [
            (0, 1),  // owner prio
            (1, 1),  // nonce first
            (2, 1),  // order prio
            (3, 1),  // seen first
            (4, 1),  // order prio
            (6, 2),  // owner k2
            (7, 2),  // nonce k2
            (8, 1),  // nonce prev
            (9, 2),  // nonce root
            (10, 5), // order k5
            (11, 5), // seen k5
            (12, 1), // seen demot
            (13, 5), // seen root
        ];
        for &(h, k) in &WANT {
            let p = &o[h];
            let key0 = match p.len() {
                SEEN_NODE_BYTES | NONCE_NODE_BYTES => p[RESTING_KEY_OFF],
                PRIO_ORDER_BYTES | PRIO_OWNER_BYTES => p[NODE_DOMAIN_LEN],
                _ => panic!("hidx {h}"),
            };
            assert_eq!(key0, k, "hidx={h}");
        }
        assert_eq!(HIDX_NONCE_K2, 7);
        assert_eq!(HIDX_SEEN_K5, 11);
        assert_eq!(HIDX_SEEN_DEMOT, 12);
        assert_eq!(HIDX_SEEN_ROOT, 13);
        assert_eq!(HIDX_OWNER_K2, 6);
        assert_eq!(HIDX_ORDER_K5, 10);
    }

    #[test]
    fn height_inc_header_vs_statement() {
        use clob::testutil::{btree_engine_v1, limit_v1};
        use protocol_types::{Height, Input, Side, TimeSeq};
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let inputs = vec![
            Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit_v1(5, 2, Side::Buy, 10, 100, 1)),
        ];
        e.apply_all(inputs);
        let pre = e.incremental_root_preimage();
        let (h, t, instr) = e.incremental_header();
        assert_eq!(&pre[..INC_DOMAIN_LEN], commitments::INC_DOMAIN);
        assert_eq!(
            u16::from_le_bytes(pre[INC_DOMAIN_LEN..INC_DOMAIN_LEN + 2].try_into().unwrap()),
            protocol_types::ENCODING_VERSION
        );
        assert_eq!(&pre[INC_HEIGHT_TAG_OFF..INC_HEIGHT_TAG_OFF + 6], &INC_HEIGHT_TAG);
        assert_eq!(h, Height(THIS_HEIGHT));
        assert_eq!(t, TimeSeq(THIS_NEXT_TIME));
        assert_eq!(
            u64::from_le_bytes(pre[INC_HEIGHT_OFF..INC_HEIGHT_OFF + 8].try_into().unwrap()),
            THIS_HEIGHT
        );
        assert_eq!(
            u64::from_le_bytes(pre[INC_NEXT_T_OFF..INC_NEXT_T_OFF + 8].try_into().unwrap()),
            THIS_NEXT_TIME
        );
        assert_eq!(&pre[INC_INSTR_OFF..INC_INSTR_OFF + 32], &instr.0);
        assert_eq!(
            &pre[INC_NONCES_TAG_OFF..INC_NONCES_TAG_OFF + 6],
            &INC_NONCES_TAG
        );
        assert_eq!(
            u64::from_le_bytes(pre[INC_NONCES_TAG_OFF + 6..NONCE_ROOT_OFF].try_into().unwrap()),
            INC_DIGEST_LEN
        );
        assert_eq!(
            &pre[INC_SEENID_TAG_OFF..INC_SEENID_TAG_OFF + 6],
            &INC_SEENID_TAG
        );
        assert_eq!(
            u64::from_le_bytes(pre[INC_SEENID_TAG_OFF + 6..SEEN_ROOT_OFF].try_into().unwrap()),
            INC_DIGEST_LEN
        );
        assert_eq!(
            &pre[INC_BOOKS_TAG_OFF..INC_BOOKS_TAG_OFF + 5],
            &INC_BOOKS_TAG
        );
        assert_eq!(
            u64::from_le_bytes(pre[INC_BOOKS_TAG_OFF + 5..REST_ROOT_OFF].try_into().unwrap()),
            INC_DIGEST_LEN
        );
        let words = this_height_inc_header_words();
        for (i, word) in words.iter().enumerate() {
            let got = u32::from_le_bytes(pre[i * 4..i * 4 + 4].try_into().unwrap());
            assert_eq!(got, *word);
        }
        assert_eq!(&pre[..INC_HEADER_WORDS * 4], {
            let mut b = [0u8; INC_HEADER_WORDS * 4];
            for (i, w) in words.iter().enumerate() {
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            b
        });
    }

    #[test]
    fn height_genesis_inc_is_pre_root() {
        use clob::testutil::btree_engine_v1;
        let e = btree_engine_v1();
        let pre = e.incremental_root_preimage();
        let gen = genesis_inc_preimage();
        assert_eq!(pre, gen);
        assert_eq!(pre.len(), INC_ROOT_BYTES);
        assert_eq!(&gen[..INC_DOMAIN_LEN], commitments::INC_DOMAIN);
        assert_eq!(
            u16::from_le_bytes(gen[INC_DOMAIN_LEN..INC_DOMAIN_LEN + 2].try_into().unwrap()),
            protocol_types::ENCODING_VERSION
        );
        assert_eq!(&gen[INC_HEIGHT_TAG_OFF..INC_HEIGHT_TAG_OFF + 6], &INC_HEIGHT_TAG);
        assert_eq!(blake3_hash_msg(&gen), e.state_root().0);
        assert_eq!(
            u64::from_le_bytes(gen[INC_NEXT_T_OFF..INC_NEXT_T_OFF + 8].try_into().unwrap()),
            GENESIS_NEXT_TIME
        );
        let empty = commitments::treap_empty_digest();
        assert_eq!(&gen[NONCE_ROOT_OFF..NONCE_ROOT_OFF + 32], &empty.0);
        assert_eq!(&gen[SEEN_ROOT_OFF..SEEN_ROOT_OFF + 32], &empty.0);
        assert_eq!(&gen[REST_ROOT_OFF..REST_ROOT_OFF + 32], &empty.0);
        let o = cached_height_match_openings();
        let incs: Vec<_> = o.iter().filter(|p| p.len() == INC_ROOT_BYTES).collect();
        assert_eq!(incs.len(), 3);
        assert_eq!(incs[0], &gen);
        assert_ne!(incs[1], &gen);
        assert_ne!(incs[2], &gen);
        assert_eq!(o.last().unwrap(), incs[2]);
        assert_eq!(incs[1], &fixture_mid_inc_preimage());
        let sett = o
            .iter()
            .find(|p| p.len() == SETTLEMENT_COMMIT_BYTES)
            .expect("settlement");
        assert_eq!(opening_nblocks(sett.len()), 5);
        assert_eq!(opening_last_blen(sett.len()), 21);
        assert_eq!(sett, &fixture_settlement_preimage());
        let payload = {
            use clob::testutil::btree_engine_v1;
            let mut e = btree_engine_v1();
            e.set_treap_hash(clob::TreapHash::Blake3Count);
            let deltas: Vec<_> = e
                .apply_all(crossing_inputs())
                .into_iter()
                .flat_map(|r| r.settlement)
                .collect();
            commitments::commit_list_payload(&deltas)
        };
        assert_eq!(
            blake3_hash_msg(sett),
            commitments::Digest::from_bytes(&payload, commitments::RECEIPT_DOMAIN).0
        );
    }

    #[test]
    fn height_resting_leaf_is_match_rest() {
        let (key, value) = unit_resting_kv();
        let empty = [0u8; 32];
        let unit = node_preimage(empty, &key, &value, empty);
        assert_eq!(unit.len(), RESTING_NODE_BYTES);
        assert_eq!(
            u64::from_le_bytes(
                unit[RESTING_QTY_OFF..RESTING_QTY_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            10
        );
        assert_eq!(
            u64::from_le_bytes(
                unit[RESTING_PRICE_OFF..RESTING_PRICE_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            90
        );
        let rest = cached_height_openings()
            .into_iter()
            .find(|p| p.len() == RESTING_NODE_BYTES)
            .expect("one resting");
        assert_eq!(
            u64::from_le_bytes(
                rest[RESTING_QTY_OFF..RESTING_QTY_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            10
        );
        assert_eq!(
            u64::from_le_bytes(
                rest[RESTING_PRICE_OFF..RESTING_PRICE_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            90
        );
        let stmt = unit_height_match_step();
        assert_eq!(stmt.instance.rest_qty.0, 10);
        assert_eq!(stmt.instance.rest_price.0, 90);
        let i = cached_height_match_openings()
            .into_iter()
            .find(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        assert_eq!(
            u64::from_le_bytes(
                i[INPUT_SELL_QTY_OFF..INPUT_SELL_QTY_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            10
        );
        assert_eq!(
            u64::from_le_bytes(
                i[INPUT_SELL_PRICE_OFF..INPUT_SELL_PRICE_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            90
        );
        assert_eq!(i[SELL_QTY_WORD * 4], 10);
        assert_eq!(i[SELL_PRICE_WORD * 4], 90);
        assert_eq!(&rest[RESTING_ID_OFF..RESTING_ID_OFF + 16], &i[INPUT_SELL_ID_OFF..INPUT_SELL_ID_OFF + 16]);
        assert_eq!(&rest[RESTING_INST_OFF..RESTING_INST_OFF + 4], &i[INPUT_SELL_INST_OFF..INPUT_SELL_INST_OFF + 4]);
        assert_eq!(rest[RESTING_SIDE_OFF], i[INPUT_SELL_SIDE_OFF]);
        assert_eq!(i[INPUT_SELL_ID_OFF], MAKER_ORDER_ID_BYTE as u8);
        assert_eq!(
            u32::from_le_bytes(i[INPUT_SELL_INST_OFF..INPUT_SELL_INST_OFF + 4].try_into().unwrap()),
            INSTRUMENT_ID_BYTE as u32
        );
        assert_eq!(i[INPUT_SELL_SIDE_OFF], SELL_SIDE_BYTE as u8);
        assert_eq!(
            u64::from_le_bytes(
                rest[RESTING_EXPIRY_OFF..RESTING_EXPIRY_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            EXPIRY_HEIGHT
        );
        assert_eq!(
            u64::from_le_bytes(
                rest[RESTING_NONCE_OFF..RESTING_NONCE_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            ORDER_NONCE
        );
        assert_eq!(
            &rest[RESTING_EXPIRY_OFF..RESTING_NONCE_OFF + 8],
            &i[INPUT_SELL_EXPIRY_OFF..INPUT_SELL_NONCE_OFF + 8]
        );
        assert_eq!(
            u64::from_le_bytes(
                rest[RESTING_TIME_OFF..RESTING_TIME_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            GENESIS_NEXT_TIME
        );
        assert_ne!(GENESIS_NEXT_TIME, THIS_NEXT_TIME);
        let empty = commitments::treap_empty_digest().0;
        assert_eq!(&rest[RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &empty);
        assert_eq!(&rest[RESTING_RIGHT_OFF..RESTING_RIGHT_OFF + 32], &empty);
        assert_eq!(&rest[..NODE_DOMAIN_LEN], commitments::TREAP_NODE_DOMAIN);
        assert_eq!(
            u16::from_le_bytes(rest[NODE_DOMAIN_LEN..RESTING_LEFT_OFF].try_into().unwrap()),
            protocol_types::ENCODING_VERSION
        );
        assert_eq!(
            u64::from_le_bytes(
                rest[RESTING_KEY_LEN_OFF..RESTING_KEY_OFF]
                    .try_into()
                    .unwrap()
            ),
            RESTING_KEY_LEN
        );
        assert_eq!(&rest[RESTING_KEY_OFF..RESTING_VALUE_LEN_OFF], key.as_slice());
        assert_eq!(
            u64::from_le_bytes(
                rest[RESTING_VALUE_LEN_OFF..RESTING_TAG_OFF]
                    .try_into()
                    .unwrap()
            ),
            RESTING_VALUE_LEN
        );
        assert_eq!(&rest[RESTING_TAG_OFF..RESTING_ID_OFF], &RESTING_TAG);
        assert_eq!(value.len() as u64, RESTING_VALUE_LEN);
    }

    #[test]
    fn height_i_is_match_take() {
        let pre = input_commit_preimage(&crossing_inputs());
        assert_eq!(pre.len(), INPUT_COMMIT_BYTES);
        assert_eq!(opening_nblocks(pre.len()), 4);
        assert_eq!(opening_last_blen(pre.len()), 41);
        assert_eq!(&pre[..NODE_DOMAIN_LEN], commitments::INPUT_DOMAIN);
        assert_eq!(
            u16::from_le_bytes(pre[NODE_DOMAIN_LEN..NODE_DOMAIN_LEN + 2].try_into().unwrap()),
            protocol_types::ENCODING_VERSION
        );
        assert_eq!(
            u64::from_le_bytes(pre[NODE_DOMAIN_LEN + 2..INPUT_PLACE0_OFF - 4].try_into().unwrap()),
            INPUT_PAYLOAD_LEN
        );
        assert_eq!(
            u32::from_le_bytes(pre[INPUT_PLACE0_OFF - 4..INPUT_PLACE0_OFF].try_into().unwrap()),
            INPUT_COUNT as u32
        );
        assert_eq!(&pre[INPUT_PLACE0_OFF..INPUT_ORDER0_OFF], &INPUT_PLACE_TAG);
        assert_eq!(&pre[INPUT_ORDER0_OFF..INPUT_SELL_ID_OFF], &INPUT_ORDER_TAG);
        assert_eq!(&pre[INPUT_PLACE1_OFF..INPUT_ORDER1_OFF], &INPUT_PLACE_TAG);
        assert_eq!(&pre[INPUT_ORDER1_OFF..INPUT_TAKE_ID_OFF], &INPUT_ORDER_TAG);
        let payload = commitments::commit_list_payload(&crossing_inputs());
        assert_eq!(
            blake3_hash_msg(&pre),
            commitments::Digest::from_bytes(&payload, commitments::INPUT_DOMAIN).0
        );
        assert_eq!(
            u64::from_le_bytes(
                pre[INPUT_TAKE_QTY_OFF..INPUT_TAKE_QTY_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            10
        );
        assert_eq!(
            u64::from_le_bytes(
                pre[INPUT_TAKE_PRICE_OFF..INPUT_TAKE_PRICE_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            100
        );
        assert_eq!(pre[TAKE_QTY_WORD * 4], 0);
        assert_eq!(pre[TAKE_QTY_WORD * 4 + 1], 10);
        assert_eq!(pre[TAKE_PRICE_WORD * 4], 0);
        assert_eq!(pre[TAKE_PRICE_WORD * 4 + 1], 100);
        assert_eq!(pre[INPUT_TAKE_ID_OFF], TAKER_ORDER_ID_BYTE as u8);
        assert!(pre[INPUT_TAKE_ID_OFF + 1..INPUT_TAKE_ID_OFF + 16].iter().all(|x| *x == 0));
        assert_eq!(
            u32::from_le_bytes(pre[INPUT_TAKE_INST_OFF..INPUT_TAKE_INST_OFF + 4].try_into().unwrap()),
            INSTRUMENT_ID_BYTE as u32
        );
        assert_eq!(
            u64::from_le_bytes(
                pre[INPUT_TAKE_EXPIRY_OFF..INPUT_TAKE_EXPIRY_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            EXPIRY_HEIGHT
        );
        assert_eq!(
            u64::from_le_bytes(
                pre[INPUT_TAKE_NONCE_OFF..INPUT_TAKE_NONCE_OFF + 8]
                    .try_into()
                    .unwrap()
            ),
            ORDER_NONCE
        );
        assert_eq!(pre.len(), INPUT_TAKE_NONCE_OFF + 8);
        let openings = cached_height_match_openings();
        let i = openings
            .iter()
            .find(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        assert_eq!(i, &pre);
        let last = openings.last().unwrap();
        assert_eq!(last.len(), INC_ROOT_BYTES);
        assert_eq!(opening_nblocks(last.len()), 4);
        assert_eq!(opening_last_blen(last.len()), 52);
        let post = unit_height_openings().1;
        assert_eq!(blake3_hash_msg(last), post);
        let stmt = unit_height_match_step();
        assert_eq!(stmt.instance.take_qty.0, 10);
        assert_eq!(stmt.instance.take_price.0, 100);
        assert_eq!(openings.len(), HEIGHT_MATCH_OPENINGS);
        // Rotate fixture: 9 node (4 seen×2 + 4 nonce×3 + 1 rest×4) + 5 prio
        // + I (4) + three INC (4 each) + settlement (5) = 50 blocks.
        let blocks: usize = openings.iter().map(|p| opening_nblocks(p.len())).sum();
        assert_eq!(blocks * C_ROWS, 3200);
        assert!(blocks * C_ROWS < HM_ROWS);
    }

    #[test]
    fn height_settlement_amounts_are_match_fill() {
        let sett = fixture_settlement_preimage();
        assert_eq!(sett.len(), SETTLEMENT_COMMIT_BYTES);
        assert_eq!(&sett[..RECEIPT_DOMAIN_LEN], commitments::RECEIPT_DOMAIN);
        assert_eq!(
            u16::from_le_bytes(
                sett[RECEIPT_DOMAIN_LEN..RECEIPT_DOMAIN_LEN + 2]
                    .try_into()
                    .unwrap()
            ),
            protocol_types::ENCODING_VERSION
        );
        assert_eq!(
            u64::from_le_bytes(
                sett[RECEIPT_DOMAIN_LEN + 2..SETTLE_DELTA0_OFF - 4]
                    .try_into()
                    .unwrap()
            ),
            RECEIPT_PAYLOAD_LEN
        );
        assert_eq!(
            u32::from_le_bytes(sett[SETTLE_DELTA0_OFF - 4..SETTLE_DELTA0_OFF].try_into().unwrap()),
            RECEIPT_COUNT as u32
        );
        for i in 0..RECEIPT_COUNT as usize {
            let off = SETTLE_DELTA0_OFF + i * SETTLE_DELTA_LEN;
            assert_eq!(&sett[off..off + 8], &RECEIPT_DELTA_TAG);
        }
        assert_eq!(settle_debit_off(1), SETTLE_DELTA0_OFF + SETTLE_DELTA_LEN + SETTLE_DEBIT_IN_DELTA);
        assert_eq!(sett[settle_debit_off(1)], SETTLE_DEBIT1 as u8);
        assert_eq!(settle_amt_off(0), 77);
        assert_eq!(settle_amt_off(1), 138);
        assert_eq!(settle_amt_off(2), 199);
        assert_eq!(settle_amt_off(3), 260);
        let amt = |i: usize| u128::from_le_bytes(sett[settle_amt_off(i)..settle_amt_off(i) + 16].try_into().unwrap());
        let debit = |i: usize| sett[settle_debit_off(i)];
        assert_eq!(amt(0), u128::from(SETTLE_FILL_AMT));
        assert_eq!(amt(1), u128::from(SETTLE_QUOTE_AMT));
        assert_eq!(amt(2), u128::from(SETTLE_FILL_AMT));
        assert_eq!(amt(3), u128::from(SETTLE_QUOTE_AMT));
        assert_eq!(debit(0), 0);
        assert_eq!(debit(1), 1);
        assert_eq!(debit(2), 1);
        assert_eq!(debit(3), 0);
        let w19 = u32::from_le_bytes(sett[76..80].try_into().unwrap());
        assert_eq!(w19, (SETTLE_FILL_AMT << 8) as u32);
        let w34h = u16::from_le_bytes(sett[138..140].try_into().unwrap());
        assert_eq!(w34h as u64, SETTLE_QUOTE_AMT);
        let w49h = u16::from_le_bytes(sett[198..200].try_into().unwrap());
        assert_eq!(w49h as u64, SETTLE_FILL_AMT << 8);
        let w5 = u32::from_le_bytes(sett[260..264].try_into().unwrap());
        assert_eq!(w5 as u64, SETTLE_QUOTE_AMT);
        let stmt = unit_height_match_step();
        assert_eq!(stmt.output.fill_qty.0, SETTLE_FILL_AMT);
        assert_eq!(stmt.output.notional, u128::from(SETTLE_QUOTE_AMT));
        let openings = cached_height_match_openings();
        let in_tape = openings
            .iter()
            .find(|p| p.len() == SETTLEMENT_COMMIT_BYTES)
            .unwrap();
        assert_eq!(in_tape, &sett);
    }

    fn from_byte_owner_at(buf: &[u8], off: usize, b: u8) {
        assert_eq!(buf[off], b);
        assert!(buf[off + 1..off + 32].iter().all(|x| *x == 0));
    }

    #[test]
    fn height_settlement_owners_are_rest_and_take() {
        let openings = cached_height_match_openings();
        let rest = openings
            .iter()
            .find(|p| p.len() == RESTING_NODE_BYTES)
            .expect("rest");
        let i = openings
            .iter()
            .find(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        let sett = openings
            .iter()
            .find(|p| p.len() == SETTLEMENT_COMMIT_BYTES)
            .expect("settlement");
        assert_eq!(settle_owner_off(0), 41);
        assert_eq!(settle_owner_off(1), 102);
        assert_eq!(settle_owner_off(2), 163);
        assert_eq!(settle_owner_off(3), 224);
        assert_eq!(settle_asset_off(0), 73);
        assert_eq!(settle_asset_off(1), 134);
        assert_eq!(settle_asset_off(2), 195);
        assert_eq!(settle_asset_off(3), 256);
        from_byte_owner_at(rest, RESTING_OWNER_OFF, MAKER_OWNER_BYTE as u8);
        from_byte_owner_at(i, INPUT_TAKE_OWNER_OFF, TAKER_OWNER_BYTE as u8);
        from_byte_owner_at(i, INPUT_SELL_OWNER_OFF, MAKER_OWNER_BYTE as u8);
        from_byte_owner_at(sett, settle_owner_off(0), TAKER_OWNER_BYTE as u8);
        from_byte_owner_at(sett, settle_owner_off(1), TAKER_OWNER_BYTE as u8);
        from_byte_owner_at(sett, settle_owner_off(2), MAKER_OWNER_BYTE as u8);
        from_byte_owner_at(sett, settle_owner_off(3), MAKER_OWNER_BYTE as u8);
        assert_eq!(
            u32::from_le_bytes(sett[settle_asset_off(0)..settle_asset_off(0) + 4].try_into().unwrap()),
            BASE_ASSET as u32
        );
        assert_eq!(
            u32::from_le_bytes(sett[settle_asset_off(1)..settle_asset_off(1) + 4].try_into().unwrap()),
            QUOTE_ASSET as u32
        );
        assert_eq!(
            u32::from_le_bytes(sett[settle_asset_off(2)..settle_asset_off(2) + 4].try_into().unwrap()),
            BASE_ASSET as u32
        );
        assert_eq!(
            u32::from_le_bytes(sett[settle_asset_off(3)..settle_asset_off(3) + 4].try_into().unwrap()),
            QUOTE_ASSET as u32
        );
        let w54 = u32::from_le_bytes(i[216..220].try_into().unwrap());
        assert_eq!(w54, 0x0003_e800);
        assert_eq!(u16::from_le_bytes(i[184..186].try_into().unwrap()), (TAKER_OWNER_BYTE << 8) as u16);
        assert_eq!(rest[128], 1);
        assert_eq!(i[185], 2);
        assert_eq!(i[84], 1);
    }

    #[test]
    fn height_openings_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &HeightOpeningsAir,
            AirLayout::from_air::<Val>(&HeightOpeningsAir),
        );
        eprintln!("blake3 height_openings AIR max constraint degree {d}");
        assert_eq!(d, 2);
    }

    #[test]
    fn prove_height_openings() {
        let preimages = cached_height_openings();
        let (proof, report) =
            prove_height_openings_and_report_with(preimages, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 height-openings n={} test: prove {} ms, verify {} ms, {} bytes, FRI {} (14 C' hashes = 9 node + 5 prio of HeightStatement height, not F, not matching, last digest != post_root, not 72/281/363497)",
            HEIGHT_OPENINGS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_height_openings_prod() {
        let preimages = cached_height_openings();
        let (_, report) = prove_height_openings_and_report_with(preimages, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 height-openings n={} prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (14 C' hashes, not F, not matching)",
            HEIGHT_OPENINGS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_height_openings_prod_again() {
        let preimages = cached_height_openings();
        let (_, report) = prove_height_openings_and_report_with(preimages, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 height-openings n={} prod run2: prove {} ms, verify {} ms, {} bytes (14 C' hashes, not F, not matching)",
            HEIGHT_OPENINGS, report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }

    fn unit_height_match_step() -> tiny_f::MatchStepStatement {
        tiny_f::MatchStepStatement::prove_native(tiny_f::MatchStepInstance {
            rest_qty: protocol_types::Qty(10),
            rest_price: protocol_types::Price(90),
            take_qty: protocol_types::Qty(10),
            take_price: protocol_types::Price(100),
        })
        .unwrap()
    }

    #[test]
    fn height_match_mid_equals_resting_out() {
        let preimages = cached_height_match_openings();
        let mid = mid_books_from_openings(&preimages).unwrap();
        assert_eq!(HEIGHT_MATCH_OPENINGS, 19);
        assert_ne!(mid, commitments::treap_empty_digest().0);
        let stmt = unit_height_match_step();
        let proof = prove_height_match_mid(preimages.clone(), stmt, mid, FriClass::Test).unwrap();
        verify_height_match_mid(preimages, stmt, mid, &proof, FriClass::Test).unwrap();
    }

    #[test]
    fn height_match_wrong_mid_books_rejected() {
        let preimages = cached_height_match_openings();
        let stmt = unit_height_match_step();
        let mid = mid_books_from_openings(&preimages).unwrap();
        let proof = prove_height_match_mid(preimages.clone(), stmt, mid, FriClass::Test).unwrap();
        let wrong = commitments::treap_empty_digest().0;
        assert!(verify_height_match_mid(preimages, stmt, wrong, &proof, FriClass::Test).is_err());
    }

    /// Constructive: match-step fill lockstep ≠ CLOB apply; 19 ≠ 72/281/363497.
    #[test]
    fn height_match_stark_is_not_clob_apply() {
        use clob::testutil::btree_engine_v1;
        use std::time::Instant;

        let _ = commitments::take_treap_hash_calls();
        let stmt = unit_height_match_step();
        let match_calls = commitments::take_treap_hash_calls();
        assert_eq!(match_calls.prio, 0);
        assert_eq!(match_calls.node, 0);
        assert!(stmt.output.crosses);
        assert_eq!(stmt.output.fill_qty.0, 10);
        assert_eq!(stmt.output.notional, 900);

        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let _ = commitments::take_treap_hash_calls();
        commitments::start_node_digest_trace();
        commitments::start_prio_trace();
        let t0 = Instant::now();
        let receipts = e.apply_all(crossing_inputs());
        let apply_us = t0.elapsed().as_micros();
        let apply_calls = commitments::take_treap_hash_calls();
        let node_n = commitments::take_node_digest_trace().len();
        let prio_n = commitments::take_prio_trace().len();
        assert_eq!(apply_calls.prio, HEIGHT_PRIO as u64);
        assert_eq!(apply_calls.node, HEIGHT_NODE_OPENINGS as u64);
        assert_eq!(prio_n, HEIGHT_PRIO);
        assert_eq!(node_n, HEIGHT_NODE_OPENINGS);
        assert_eq!(receipts[1].fills.len(), 1);
        assert_eq!(receipts[1].fills[0].qty, stmt.output.fill_qty);

        let hm = cached_height_match_openings();
        assert_eq!(hm.len(), HEIGHT_MATCH_OPENINGS);
        assert_eq!(HEIGHT_MATCH_OPENINGS, HEIGHT_OPENINGS + 5);
        assert_eq!(HEIGHT_OPENINGS, HEIGHT_NODE_OPENINGS + HEIGHT_PRIO);
        assert_eq!(hm[hm.len() - 5].len(), INPUT_COMMIT_BYTES);
        assert_eq!(hm[hm.len() - 4].len(), INC_ROOT_BYTES); // genesis
        assert_eq!(hm[hm.len() - 3].len(), INC_ROOT_BYTES); // mid
        assert_eq!(hm[hm.len() - 2].len(), SETTLEMENT_COMMIT_BYTES);
        assert_eq!(hm[hm.len() - 1].len(), INC_ROOT_BYTES); // post
        assert_ne!(HEIGHT_MATCH_OPENINGS, ENGINE_INSERT_OPENINGS);
        assert_ne!(HEIGHT_MATCH_OPENINGS, ENGINE_TAPE_OPENINGS);
        assert_eq!(HEIGHT_MATCH_OPENINGS, NODE_PATH_LEN); // count collide; tapes differ
        assert_ne!(HEIGHT_MATCH_OPENINGS, 363_497);
        assert!(apply_us < 50_000, "native apply should be << prove grain");
        eprintln!(
            "height-match ≠ CLOB apply: match-step treap hashes=0; apply prio={} node={} ({} µs); HeightMatch openings={} = {} map + I/genesis/mid/settlement/post; ≠ {}/{} /363497",
            apply_calls.prio,
            apply_calls.node,
            apply_us,
            HEIGHT_MATCH_OPENINGS,
            HEIGHT_OPENINGS,
            ENGINE_INSERT_OPENINGS,
            ENGINE_TAPE_OPENINGS
        );
    }

    #[test]
    fn height_match_locksteps_clob_fill() {
        use clob::testutil::{btree_engine_v1, limit_v1};
        use protocol_types::{Input, Qty, Side};
        let mut e = btree_engine_v1();
        e.set_treap_hash(clob::TreapHash::Blake3Count);
        let receipts = e.apply_all(vec![
            Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit_v1(5, 2, Side::Buy, 10, 100, 1)),
        ]);
        assert!(receipts[0].fills.is_empty());
        assert_eq!(receipts[1].fills.len(), 1);
        let f = &receipts[1].fills[0];
        let stmt = unit_height_match_step();
        assert!(stmt.output.crosses);
        assert_eq!(stmt.output.fill_qty, f.qty);
        assert_eq!(stmt.output.fill_price, f.price);
        assert_eq!(stmt.output.remainder, Qty(0));
        assert_eq!(stmt.output.notional, 900);
        let last = blake3_hash_msg(&cached_height_match_openings().last().unwrap());
        assert_eq!(last, e.state_root().0);
        let payload = commitments::commit_list_payload(&crossing_inputs());
        let i = cached_height_match_openings()
            .into_iter()
            .find(|p| p.len() == INPUT_COMMIT_BYTES)
            .unwrap();
        assert_eq!(
            blake3_hash_msg(&i),
            commitments::Digest::from_bytes(&payload, commitments::INPUT_DOMAIN).0
        );
    }

    #[test]
    fn height_match_wrong_rest_rejected() {
        let preimages = cached_height_match_openings();
        let stmt = unit_height_match_step();
        let proof = prove_height_match_with(preimages.clone(), stmt, FriClass::Test).unwrap();
        let other = tiny_f::MatchStepStatement::prove_native(tiny_f::MatchStepInstance {
            rest_qty: protocol_types::Qty(9),
            rest_price: protocol_types::Price(90),
            take_qty: protocol_types::Qty(10),
            take_price: protocol_types::Price(100),
        })
        .unwrap();
        assert!(verify_height_match_with(preimages, other, &proof, FriClass::Test).is_err());
    }

    #[test]
    fn height_match_wrong_take_rejected() {
        let preimages = cached_height_match_openings();
        let stmt = unit_height_match_step();
        let proof = prove_height_match_with(preimages.clone(), stmt, FriClass::Test).unwrap();
        let other = tiny_f::MatchStepStatement::prove_native(tiny_f::MatchStepInstance {
            rest_qty: protocol_types::Qty(10),
            rest_price: protocol_types::Price(90),
            take_qty: protocol_types::Qty(9),
            take_price: protocol_types::Price(100),
        })
        .unwrap();
        assert!(verify_height_match_with(preimages, other, &proof, FriClass::Test).is_err());
    }

    #[test]
    fn height_match_wrong_settlement_amount_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == SETTLEMENT_COMMIT_BYTES)
            .expect("settlement");
        preimages[i][settle_amt_off(0)] = 11;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_settlement_owner_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == SETTLEMENT_COMMIT_BYTES)
            .expect("settlement");
        preimages[i][settle_owner_off(0)] = 3;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_i_sell_owner_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        preimages[i][INPUT_SELL_OWNER_OFF] = 3;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_i_sell_qty_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        preimages[i][INPUT_SELL_QTY_OFF] = 9;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_i_sell_id_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        preimages[i][INPUT_SELL_ID_OFF] = 3;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_i_take_id_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        preimages[i][INPUT_TAKE_ID_OFF] = 3;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_i_sell_nonce_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        preimages[i][INPUT_SELL_NONCE_OFF] = 2;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_i_take_nonce_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        preimages[i][INPUT_TAKE_NONCE_OFF] = 2;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_rest_time_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == RESTING_NODE_BYTES)
            .expect("rest");
        preimages[i][RESTING_TIME_OFF] = 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_rest_tag_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == RESTING_NODE_BYTES)
            .expect("rest");
        preimages[i][RESTING_TAG_OFF] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_seen_domain_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == SEEN_NODE_BYTES)
            .expect("seen");
        preimages[i][0] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_inc_is_inc_domain() {
        let o = cached_height_match_openings();
        let incs: Vec<_> = o.iter().filter(|p| p.len() == INC_ROOT_BYTES).collect();
        assert_eq!(incs.len(), 3);
        for pre in &incs {
            assert_eq!(&pre[..INC_DOMAIN_LEN], commitments::INC_DOMAIN);
            assert_eq!(
                u16::from_le_bytes(pre[INC_DOMAIN_LEN..INC_DOMAIN_LEN + 2].try_into().unwrap()),
                protocol_types::ENCODING_VERSION
            );
            assert_eq!(
                &pre[INC_HEIGHT_TAG_OFF..INC_HEIGHT_TAG_OFF + 6],
                &INC_HEIGHT_TAG
            );
            assert_eq!(
                u64::from_le_bytes(
                    pre[INC_HEIGHT_TAG_OFF + 6..INC_HEIGHT_OFF]
                        .try_into()
                        .unwrap()
                ),
                INC_HEIGHT_LEN
            );
            assert_eq!(
                u64::from_le_bytes(pre[INC_HEIGHT_OFF..INC_HEIGHT_OFF + 8].try_into().unwrap()),
                THIS_HEIGHT
            );
        }
        assert_eq!(incs[0], &genesis_inc_preimage());
        assert_eq!(incs[1], &fixture_mid_inc_preimage());
        assert_eq!(o.last().unwrap(), incs[2]);
        assert_ne!(incs[0], incs[1]);
        assert_ne!(incs[1], incs[2]);
        assert_eq!(opening_last_blen(INC_ROOT_BYTES), 52);
        assert_eq!(INC_DOMAIN_LEN, 15);
        assert_eq!(commitments::INC_DOMAIN, b"plx/clob/inc/v1");
        let w3 = u32::from_le_bytes(incs[1][12..16].try_into().unwrap());
        assert_eq!(
            w3,
            u32::from(incs[1][12])
                | u32::from(incs[1][13]) << 8
                | u32::from(incs[1][14]) << 16
                | u32::from(protocol_types::ENCODING_VERSION) << 24
        );
        assert_eq!(incs[1][14], b'1');
        assert_eq!(incs[1][16], 0);
        assert_eq!(&incs[1][17..23], b"height");
        assert_eq!(incs[1][23], INC_HEIGHT_LEN as u8);
        let post = incs[2];
        assert_eq!(&post[INC_NONCES_TAG_OFF..NONCE_ROOT_OFF - 8], &INC_NONCES_TAG);
        assert_eq!(
            u64::from_le_bytes(post[NONCE_ROOT_OFF - 8..NONCE_ROOT_OFF].try_into().unwrap()),
            INC_DIGEST_LEN
        );
        assert_eq!(&post[INC_SEENID_TAG_OFF..SEEN_ROOT_OFF - 8], &INC_SEENID_TAG);
        assert_eq!(post[153], b's');
        assert_eq!(post[166], 0);
        assert_eq!(&post[INC_BOOKS_TAG_OFF..REST_ROOT_OFF - 8], &INC_BOOKS_TAG);
        assert_eq!(post[199], b'b');
        assert_eq!(
            u64::from_le_bytes(post[REST_ROOT_OFF - 8..REST_ROOT_OFF].try_into().unwrap()),
            INC_DIGEST_LEN
        );
        assert_eq!(INC_HEADER_WORDS * 4, 108);
        assert_eq!(post[108], b'o');
    }

    #[test]
    fn height_inc_map_tags() {
        let o = cached_height_match_openings();
        let post = o.last().expect("post");
        assert_eq!(post.len(), INC_ROOT_BYTES);
        assert_eq!(&post[107..113], b"nonces");
        assert_eq!(&post[153..159], b"seenid");
        assert_eq!(&post[199..204], b"books");
        assert_eq!(u64::from_le_bytes(post[113..121].try_into().unwrap()), 32);
        assert_eq!(u64::from_le_bytes(post[159..167].try_into().unwrap()), 32);
        assert_eq!(u64::from_le_bytes(post[204..212].try_into().unwrap()), 32);
        assert_ne!(post[121], post[0]);
        let gen = o
            .iter()
            .find(|p| p.len() == INC_ROOT_BYTES)
            .expect("genesis");
        assert_eq!(&gen[107..113], b"nonces");
        assert_eq!(&gen[153..159], b"seenid");
        assert_eq!(&gen[199..204], b"books");
        assert_ne!(&post[121..153], &gen[121..153]);
    }

    #[test]
    fn height_match_wrong_i_domain_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == INPUT_COMMIT_BYTES)
            .expect("I");
        preimages[i][0] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_settlement_is_receipt_domain() {
        let sett = fixture_settlement_preimage();
        assert_eq!(commitments::RECEIPT_DOMAIN, b"plx/clob/receipt/v1");
        assert_eq!(RECEIPT_DOMAIN_LEN, 19);
        assert_eq!(sett.len(), 277);
        assert_eq!(&sett[..RECEIPT_DOMAIN_LEN], commitments::RECEIPT_DOMAIN);
        assert_eq!(sett[18], b'1');
        assert_eq!(
            u16::from_le_bytes(sett[19..21].try_into().unwrap()),
            protocol_types::ENCODING_VERSION
        );
        assert_eq!(u64::from_le_bytes(sett[21..29].try_into().unwrap()), 248);
        assert_eq!(u32::from_le_bytes(sett[29..33].try_into().unwrap()), 4);
        assert_eq!(&sett[33..41], b"DELTA\0\0\0");
        assert_eq!(&sett[94..102], b"DELTA\0\0\0");
        assert_eq!(&sett[155..163], b"DELTA\0\0\0");
        assert_eq!(&sett[216..224], b"DELTA\0\0\0");
        assert_eq!(sett[154], SETTLE_DEBIT1 as u8);
        let w38h = u16::from_le_bytes(sett[154..156].try_into().unwrap());
        assert_eq!(w38h, SETTLE_DEBIT1 as u16 | u16::from(b'D') << 8);
        let o = cached_height_match_openings();
        let in_tape = o
            .iter()
            .find(|p| p.len() == SETTLEMENT_COMMIT_BYTES)
            .expect("settlement");
        assert_eq!(in_tape, &sett);
        assert_eq!(opening_last_blen(sett.len()), 21);
        assert_eq!(opening_nblocks(sett.len()), 5);
    }

    #[test]
    fn height_match_wrong_inc_domain_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .rposition(|p| p.len() == INC_ROOT_BYTES)
            .expect("post INC");
        preimages[i][0] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_inc_map_tag_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .rposition(|p| p.len() == INC_ROOT_BYTES)
            .expect("post INC");
        preimages[i][INC_NONCES_TAG_OFF + 1] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_receipt_domain_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == SETTLEMENT_COMMIT_BYTES)
            .expect("settlement");
        preimages[i][0] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_nonce_root_left_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.len() == NONCE_NODE_BYTES)
            .nth(3)
            .map(|(i, _)| i)
            .expect("nonce root");
        preimages[i][RESTING_LEFT_OFF] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_seen_root_left_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.len() == SEEN_NODE_BYTES)
            .nth(3)
            .map(|(i, _)| i)
            .expect("seen rotate root");
        preimages[i][RESTING_LEFT_OFF] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_seen_left_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == SEEN_NODE_BYTES)
            .expect("seen");
        preimages[i][RESTING_LEFT_OFF] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_seen_key_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == SEEN_NODE_BYTES)
            .expect("seen");
        preimages[i][RESTING_KEY_OFF] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_prio_domain_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == PRIO_ORDER_BYTES)
            .expect("prio");
        preimages[i][0] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_wrong_rest_right_rejected() {
        let mut preimages = cached_height_match_openings();
        let i = preimages
            .iter()
            .position(|p| p.len() == RESTING_NODE_BYTES)
            .expect("rest");
        preimages[i][RESTING_RIGHT_OFF] ^= 1;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    #[test]
    fn height_match_constraint_degree() {
        use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
        let d = get_max_constraint_degree::<Val, _>(
            &HeightMatchAir,
            AirLayout::from_air::<Val>(&HeightMatchAir),
        );
        eprintln!("blake3 height_match AIR max constraint degree {d}");
        assert_eq!(d, 3);
    }

    /// Constructive: heap_before on edges 5←4 (OwnerId) and 8←7 (OrderId).
    #[test]
    fn height_match_prio_heap_edges() {
        use commitments::prio_preimage;
        let hm = cached_height_match_openings();
        let mut k1 = [0u8; 32];
        k1[0] = 1;
        let mut k2 = [0u8; 32];
        k2[0] = 2;
        let mut o1 = [0u8; 16];
        o1[0] = 1;
        let mut o5 = [0u8; 16];
        o5[0] = 5;
        let prio = |key: &[u8]| {
            let pre = prio_preimage(key);
            let out = blake3_hash_msg(&pre);
            u64::from_le_bytes(out[..8].try_into().unwrap())
        };
        let pn1 = prio(&k1);
        let pn2 = prio(&k2);
        let po1 = prio(&o1);
        let po5 = prio(&o5);
        // heap_before(child, parent) must be false on both edges.
        assert!(!(pn1 > pn2 || (pn1 == pn2 && k1.as_slice() < k2.as_slice())));
        assert!(!(po1 > po5 || (po1 == po5 && o1.as_slice() < o5.as_slice())));
        assert!(pn2 > pn1);
        assert!(po5 > po1);
        let owners: Vec<_> = hm
            .iter()
            .filter(|p| p.len() == PRIO_OWNER_BYTES)
            .collect();
        let orders: Vec<_> = hm
            .iter()
            .filter(|p| p.len() == PRIO_ORDER_BYTES)
            .collect();
        assert_eq!(owners.len(), 2);
        assert_eq!(orders.len(), 3);
        assert_eq!(HEIGHT_MATCH_OPENINGS, 19);
    }

    /// Constructive: BST on chrono edges 9←8 / 13←12 (left child key < parent).
    #[test]
    fn height_match_bst_edges() {
        let hm = cached_height_match_openings();
        let key0 = |p: &[u8]| p[RESTING_KEY_OFF];
        let n_np = &hm[HIDX_NONCE_PREV as usize];
        let n_nr = &hm[HIDX_NONCE_ROOT as usize];
        let n_sd = &hm[HIDX_SEEN_DEMOT as usize];
        let n_sr = &hm[HIDX_SEEN_ROOT as usize];
        assert_eq!(n_np.len(), NONCE_NODE_BYTES);
        assert_eq!(n_nr.len(), NONCE_NODE_BYTES);
        assert_eq!(n_sd.len(), SEEN_NODE_BYTES);
        assert_eq!(n_sr.len(), SEEN_NODE_BYTES);
        assert!(key0(n_np) < key0(n_nr), "nonce left child key < parent");
        assert!(key0(n_sd) < key0(n_sr), "seen demoted key < rotate root");
        assert_eq!(HEIGHT_MATCH_OPENINGS, 19);
    }

    /// Constructive: non-rotate take id=2 is 8 nodes; rotate fixture is 9.
    #[test]
    fn rotate_crossing_adds_one_node() {
        use clob::testutil::{btree_engine_v1, limit_v1};
        use commitments::TreapHash;
        use protocol_types::{Input, Side};
        let non_rotate = vec![
            Input::Place(limit_v1(1, 1, Side::Sell, 10, 90, 1)),
            Input::Place(limit_v1(2, 2, Side::Buy, 10, 100, 1)),
        ];
        let rotate = crossing_inputs();
        let count = |inputs: Vec<Input>| {
            let mut e = btree_engine_v1();
            e.set_treap_hash(TreapHash::Blake3Count);
            let _ = commitments::take_treap_hash_calls();
            commitments::start_node_digest_trace();
            commitments::start_prio_trace();
            let _ = e.apply_all(inputs.iter().cloned());
            let calls = commitments::take_treap_hash_calls();
            (
                commitments::take_node_digest_trace().len(),
                commitments::take_prio_trace().len(),
                calls.node,
                calls.prio,
            )
        };
        let (nn, np, nc_n, nc_p) = count(non_rotate);
        let (rn, rp, rc_n, rc_p) = count(rotate);
        assert_eq!((nn, np), (HEIGHT_NODE_OPENINGS - 1, HEIGHT_PRIO));
        assert_eq!((nc_n as usize, nc_p as usize), (HEIGHT_NODE_OPENINGS - 1, HEIGHT_PRIO));
        assert_eq!((rn, rp), (HEIGHT_NODE_OPENINGS, HEIGHT_PRIO));
        assert_eq!((rc_n as usize, rc_p as usize), (HEIGHT_NODE_OPENINGS, HEIGHT_PRIO));
        assert_eq!(HEIGHT_MATCH_OPENINGS, 19);
        assert_ne!(HEIGHT_MATCH_OPENINGS, ENGINE_INSERT_OPENINGS);
    }


















    /// Constructive: Place1+2 insert keys (first key bytes) across prio/maps/`I`.
    #[test]
    fn height_match_insert_keys_from_i() {
        let o = cached_height_match_openings();
        let i = &o[14];
        // Place2
        assert_eq!(o[HIDX_ORDER_K5 as usize][17], o[HIDX_SEEN_K5 as usize][RESTING_KEY_OFF]);
        assert_eq!(o[HIDX_OWNER_K2 as usize][17], o[HIDX_NONCE_K2 as usize][RESTING_KEY_OFF]);
        assert_eq!(i[INPUT_TAKE_ID_OFF], o[HIDX_SEEN_K5 as usize][RESTING_KEY_OFF]);
        assert_eq!(i[INPUT_TAKE_OWNER_OFF], o[HIDX_NONCE_K2 as usize][RESTING_KEY_OFF]);
        // Place1
        assert_eq!(o[HIDX_ORDER_K1 as usize][17], o[HIDX_SEEN_FIRST as usize][RESTING_KEY_OFF]);
        assert_eq!(o[0][17], o[HIDX_NONCE_FIRST as usize][RESTING_KEY_OFF]);
        assert_eq!(i[INPUT_SELL_ID_OFF], o[HIDX_SEEN_FIRST as usize][RESTING_KEY_OFF]);
        assert_eq!(i[INPUT_SELL_OWNER_OFF], o[HIDX_NONCE_FIRST as usize][RESTING_KEY_OFF]);
        assert_eq!(o[5][RESTING_ID_OFF], o[HIDX_SEEN_FIRST as usize][RESTING_KEY_OFF]);
        // Resting-map order prio (hidx 4) + rest owner ↔ Place1 latches.
        assert_eq!(o[4][17], o[HIDX_SEEN_FIRST as usize][RESTING_KEY_OFF]);
        assert_eq!(o[5][RESTING_OWNER_OFF], o[0][17]);
    }

    /// Corrupt `I` take id so it disagrees with latched order-prio/seen key.
    #[test]
    fn height_match_wrong_insert_take_id_rejected() {
        let mut preimages = cached_height_match_openings();
        preimages[14][INPUT_TAKE_ID_OFF] = 7;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    /// Corrupt `I` sell id so it disagrees with Place1 insert latch.
    #[test]
    fn height_match_wrong_insert_sell_id_rejected() {
        let mut preimages = cached_height_match_openings();
        preimages[14][INPUT_SELL_ID_OFF] = 7;
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    /// Constructive: leaf→root left-overwrite (11→13 seen, 7→9 nonce) and demote pins.
    /// Outside left `[19..51]` the preimages match; `3≡12`, `1≡8`. AIR pins both outs.
    #[test]
    fn height_match_left_overwrite_and_demote_pins() {
        let o = cached_height_match_openings();
        let nf = HIDX_NONCE_FIRST as usize;
        let np = HIDX_NONCE_PREV as usize;
        let nk = HIDX_NONCE_K2 as usize;
        let nr = HIDX_NONCE_ROOT as usize;
        let sf = HIDX_SEEN_FIRST as usize;
        let sd = HIDX_SEEN_DEMOT as usize;
        let sk = HIDX_SEEN_K5 as usize;
        let sr = HIDX_SEEN_ROOT as usize;
        assert_eq!(o[nf], o[np], "nonce demote pin 1≡8");
        assert_eq!(o[sf], o[sd], "seen demote pin 3≡12");
        assert_eq!(&o[nk][..RESTING_LEFT_OFF], &o[nr][..RESTING_LEFT_OFF]);
        assert_eq!(&o[nk][51..], &o[nr][51..]);
        assert_eq!(&o[sk][..RESTING_LEFT_OFF], &o[sr][..RESTING_LEFT_OFF]);
        assert_eq!(&o[sk][51..], &o[sr][51..]);
        assert_ne!(
            &o[sk][RESTING_LEFT_OFF..51],
            &o[sr][RESTING_LEFT_OFF..51],
            "seen left must change"
        );
        assert_ne!(
            &o[nk][RESTING_LEFT_OFF..51],
            &o[nr][RESTING_LEFT_OFF..51],
            "nonce left must change"
        );
        let d_sf = blake3_hash_msg(&o[sf]);
        let d_sd = blake3_hash_msg(&o[sd]);
        assert_eq!(d_sf, d_sd);
        assert_eq!(&o[sr][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32], &d_sd);
        assert_eq!(HEIGHT_MATCH_OPENINGS, 19);
    }

    /// Corrupt demoted seen so out(12) ≠ out(3); rotate left still follows 12 → pin rejects.
    #[test]
    fn height_match_wrong_demote_pin_rejected() {
        let mut preimages = cached_height_match_openings();
        let sd = HIDX_SEEN_DEMOT as usize;
        let sr = HIDX_SEEN_ROOT as usize;
        // Flip a zero tail key byte on demoted; keeps length/header shape.
        preimages[sd][RESTING_KEY_OFF + 1] ^= 1;
        let d_sd = blake3_hash_msg(&preimages[sd]);
        preimages[sr][RESTING_LEFT_OFF..RESTING_LEFT_OFF + 32].copy_from_slice(&d_sd);
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }

    /// Rotate fixture: corrupt the nonce first leaf (opening 1, 139 B) so
    /// out(1) ≠ out(8); edge 9←8 still follows 8 → the demote pin rejects.
    #[test]
    fn height_match_wrong_nonce_demote_pin_rejected() {
        let mut preimages = cached_height_match_openings();
        assert_eq!(preimages[1].len(), NONCE_NODE_BYTES);
        preimages[1][RESTING_KEY_OFF + 1] ^= 1;
        // Keep opening 8 / edge 9←8 intact; only out(1) ≠ out(8).
        let stmt = unit_height_match_step();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_height_match_with(preimages.clone(), stmt, FriClass::Test)
        }));
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                assert!(verify_height_match_with(preimages, stmt, &proof, FriClass::Test).is_err());
            }
        }
    }










    #[test]
    fn prove_height_match() {
        let preimages = cached_height_match_openings();
        let stmt = unit_height_match_step();
        let (proof, report) =
            prove_height_match_and_report_with(preimages, stmt, FriClass::Test).unwrap();
        assert!(proof.bytes.len() > 32);
        eprintln!(
            "plonky3 height-match n={} test: prove {} ms, verify {} ms, {} bytes, FRI {} (14 C' hashes + I + genesis C + settlement + post C' + match-step, rotate 13←12 + demote pins 12≡3/8≡1 + heap+BST on 9←8/13←12, last digest = post_root, not F, not 72/281/363497)",
            HEIGHT_MATCH_OPENINGS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_height_match_prod() {
        let preimages = cached_height_match_openings();
        let stmt = unit_height_match_step();
        let (_, report) =
            prove_height_match_and_report_with(preimages, stmt, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 height-match n={} prod: prove {} ms, verify {} ms, {} bytes, FRI {}, PoW {} (14 C' hashes + I + genesis C + mid C + settlement + post C' + match-step, rotate 13←12, last digest = post_root, not F)",
            HEIGHT_MATCH_OPENINGS,
            report.prove_ms,
            report.verify_ms,
            report.proof_bytes,
            report.fri_queries,
            report.pow_bits
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn prove_height_match_prod_again() {
        let preimages = cached_height_match_openings();
        let stmt = unit_height_match_step();
        let (_, report) =
            prove_height_match_and_report_with(preimages, stmt, FriClass::Prod).unwrap();
        eprintln!(
            "plonky3 height-match n={} prod run2: prove {} ms, verify {} ms, {} bytes (14 C' hashes + I + genesis C + mid C + settlement + post C' + match-step, rotate 13←12, last digest = post_root, not F)",
            HEIGHT_MATCH_OPENINGS, report.prove_ms, report.verify_ms, report.proof_bytes
        );
    }
}
