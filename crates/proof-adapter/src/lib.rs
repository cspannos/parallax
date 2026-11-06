//! M6 settlement gate: inert until `π` or a full-view certificate (ADR 0011).
//!
//! Malachite decide is unchanged. This crate does not call `new_payload` without
//! an unlock. [`VerifyPi`] checks a [`HeightStatement`] (`C' = F(C, I)`).
//! A tiny-`F` STARK is a [`VerifyFragment`], not a height proof, not Groth16.
//! Public DA of that statement is validator replication ([`PublicStatementStore`])
//! at n=4. At n≫4, blobs larger than [`FULL_DOWNLOAD_MAX`] are chunk-Merkle
//! sampled ([`StripedNet`]). Coded availability is 2D RS ([`Rs2d`]): a missing
//! row reconstructs; 16 Merkle samples do not. Public sample indices are a
//! function of `blob_root`, so 16 hits are not a soundness proof of
//! reconstructability. Client-local coins ([`Rs2d::light_sample_hidden`]) are
//! not that public set. A `2^{-40}` unique-sample count is withhold-specific
//! (83 vs square, 739 vs missing row, 1211 vs 1-of-100 replica; tape k=72
//! is 94 / 3620 / 2575), not 16 hits. 83 / 94 public FS hits still do not
//! reconstruct. Tape k=72 encodes (~5.3 MB coded / ~11.8 KB sampled);
//! public FS reconstruct is 8621 openings (~6.3 MB); hidden `[1;32]` is 8421
//! (~6.2 MB); both exceed coded. Recovery takes
//! [`cheaper_public_recovery`] / [`recover_public_payload`] (and hidden twin);
//! uncoded orig beats both when offered; light 16-sample stays detection-only.
//! Not a DA chain, not `π`.
//! [`NoHeightStark`] rejects every height proof of `F`. Fourteen C' map hashes
//! of the 2-place height stacked with that height's match-step have a STARK
//! ([`HeightMatchVerifier`]); rest and take fields are bound on that fixture;
//! that is not `F` and does not unlock settlement. [`ApplyWitness`] names the
//! FULL_VIEW tape (statement + `I` + 18 openings + match-step) and checks it
//! natively against traced apply; mid-books public equals the 216 B resting
//! leaf digest (AIR); Place1 mid INC is opening 15 (AIR); post books empty;
//! [`height_match_pi_from_apply`] feeds that tape into `HeightMatchVerifier`.
//! Still not `π`, still `UNLOCKS_SETTLEMENT = false`, still
//! **19 ≠ 72 / 281 / 363497**.
#![forbid(unsafe_code)]

use std::sync::Arc;

use consensus_adapter::finality::FinalityCertificate;
use crypto_suite::{SuitePolicy, SuitePublicKey};
use evm_adapter::{ApplyError, AtomicApply, SettledHeight};
use proof_plonky3::{verify_tiny_with, FriClass, TinyProof};
use protocol_types::{AssetId, ConsensusValue, HeightStatement, OwnerId, SettlementDelta};
use tiny_f::TinyStatement;

mod apply_witness;
mod das;
mod height_match;
mod height_pi;
mod public_da;
#[cfg(feature = "risc0")]
mod risc0_f;
mod rs2d;
mod sample_soundness;

pub use apply_witness::{
    build_apply_witness, check_apply_witness, ApplyWitness, ApplyWitnessError,
};
pub use das::{
    kind_for, verify_opening, AvailabilityKind, ChunkOpening, ChunkedBlob, SampleError, StripedNet,
    DEFAULT_SAMPLES, FULL_DOWNLOAD_MAX,
};
pub use height_match::{height_match_pi_from_apply, HeightMatchVerifier};
pub use height_pi::HeightOpeningsVerifier;
pub use public_da::{NoHeightStark, PublicStatementStore};
#[cfg(feature = "risc0")]
pub use risc0_f::Risc0FVerifier;
pub use rs2d::{coded_n, data_k, ReconstructError, Rs2d, Rs2dNet};
pub use sample_soundness::{
    avoiding_squares, cheaper_hidden_recovery, cheaper_public_recovery, drop_complement,
    drop_unreconstructable_square_avoiding, light_samples_all_present,
    light_samples_all_present_hidden, min_hidden_samples_to_reconstruct,
    min_public_samples_to_reconstruct, min_samples_for_two_pow_neg, orig_beats_public_recovery,
    recover_hidden_payload, recover_public_payload, undetected_le_two_pow_neg, undetected_ratio,
    RecoveryPath,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unlock {
    /// Opaque proof bytes of a [`HeightStatement`]. A test verifier is not a
    /// SNARK. A tiny-`F` STARK is not height `π`.
    Proof(Vec<u8>),
    /// This replica executed `F` (FULL_VIEW). Not validity for light clients.
    FullViewCertificate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InertReason {
    MissingWitness,
    ProofInvalid,
    /// Statement is not this height's `C'` / `I` / deltas.
    StatementMismatch,
    /// Tiered finality is required and no certificate was given (ADR 0031).
    MissingFinality,
    /// The certificate is not 2f+1 valid signatures on this height's value.
    FinalityInvalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OnDecided {
    Inert { reason: InertReason },
    Settled(SettledHeight),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("proof rejected")]
pub struct VerifyError;

/// Height `π` verifier. The instance is [`HeightStatement`], not a fill fragment.
pub trait VerifyPi {
    /// Successful verify is a CLOB apply license only if true.
    /// Default is false until a real height STARK exists. Abstract policy
    /// tests that stand in for height `π` set it true.
    const UNLOCKS_SETTLEMENT: bool = false;

    fn verify(&self, statement: &HeightStatement, proof: &[u8]) -> Result<(), VerifyError>;
}

/// Fill-fragment STARK. Not [`VerifyPi`]. Not a CLOB apply license.
pub trait VerifyFragment {
    fn verify(&self, statement: &TinyStatement, proof: &[u8]) -> Result<(), VerifyError>;
}

/// Light-client verifier of the M6a fill fragment (Plonky3 uni-STARK).
///
/// Not height `π`. Not Groth16. Not a pairing wrap. Not a stack pick.
/// Does not implement [`VerifyPi`]: [`SettlementGate`] cannot take it.
pub struct Plonky3TinyVerifier {
    class: FriClass,
}

impl Plonky3TinyVerifier {
    /// p3-uni-stark test FRI (2 queries). Not a soundness claim.
    pub fn test() -> Self {
        Self {
            class: FriClass::Test,
        }
    }

    /// 100 queries, 16 PoW bits, official Poseidon2-16. Still not a security
    /// proof and still not height `π`.
    pub fn prod() -> Self {
        Self {
            class: FriClass::Prod,
        }
    }
}

impl VerifyFragment for Plonky3TinyVerifier {
    fn verify(&self, statement: &TinyStatement, proof: &[u8]) -> Result<(), VerifyError> {
        let parsed = TinyProof {
            bytes: proof.to_vec(),
        };
        verify_tiny_with(*statement, &parsed, self.class).map_err(|_| VerifyError)
    }
}

pub struct SettlementGate<V> {
    apply: AtomicApply,
    verifier: V,
    /// When set, settlement also needs a finality certificate (ADR 0031).
    finality: Option<(SuitePolicy, Arc<Vec<SuitePublicKey>>)>,
}

impl<V: VerifyPi> SettlementGate<V> {
    pub fn new(apply: AtomicApply, verifier: V) -> Self {
        Self { apply, verifier, finality: None }
    }

    /// Require a [`FinalityCertificate`] under `policy` against `roster` (the
    /// validators' full keys) before any height settles.
    pub fn require_finality(mut self, policy: SuitePolicy, roster: Arc<Vec<SuitePublicKey>>) -> Self {
        self.finality = Some((policy, roster));
        self
    }

    /// [`Self::on_decided`] with a finality certificate. The certificate must
    /// carry 2f+1 valid signatures on this value's id at this height.
    pub fn on_decided_final(
        &mut self,
        value: &ConsensusValue,
        deltas: &[SettlementDelta],
        statement: &HeightStatement,
        unlock: Option<&Unlock>,
        cert: Option<&FinalityCertificate>,
    ) -> Result<OnDecided, ApplyError> {
        if let Some((policy, roster)) = &self.finality {
            let Some(cert) = cert else {
                return Ok(OnDecided::Inert { reason: InertReason::MissingFinality });
            };
            if cert.height != value.height.0
                || cert.value_id != commitments::value_id(value)
                || cert.verify(*policy, roster).is_err()
            {
                return Ok(OnDecided::Inert { reason: InertReason::FinalityInvalid });
            }
        }
        self.gate(value, deltas, statement, unlock)
    }

    pub fn settled(&self) -> Option<&SettledHeight> {
        self.apply.settled()
    }

    pub fn payload_count(&self) -> u64 {
        self.apply.payload_count()
    }

    pub fn eth_get_balance(&self, account: OwnerId, asset: AssetId) -> u128 {
        self.apply.eth_get_balance(account, asset)
    }

    /// Decide is assumed to have already happened. This only gates settlement.
    ///
    /// [`HeightStatement`] must bind the decided [`ConsensusValue`]. That is
    /// not a STARK of `C'`.
    pub fn on_decided(
        &mut self,
        value: &ConsensusValue,
        deltas: &[SettlementDelta],
        statement: &HeightStatement,
        unlock: Option<&Unlock>,
    ) -> Result<OnDecided, ApplyError> {
        if self.finality.is_some() {
            return Ok(OnDecided::Inert { reason: InertReason::MissingFinality });
        }
        self.gate(value, deltas, statement, unlock)
    }

    fn gate(
        &mut self,
        value: &ConsensusValue,
        deltas: &[SettlementDelta],
        statement: &HeightStatement,
        unlock: Option<&Unlock>,
    ) -> Result<OnDecided, ApplyError> {
        if !statement.binds_value(value) {
            return Ok(OnDecided::Inert {
                reason: InertReason::StatementMismatch,
            });
        }
        match unlock {
            None => Ok(OnDecided::Inert {
                reason: InertReason::MissingWitness,
            }),
            Some(Unlock::FullViewCertificate) => self
                .apply
                .apply_decided(value, deltas)
                .map(OnDecided::Settled),
            Some(Unlock::Proof(bytes)) => match self.verifier.verify(statement, bytes) {
                Err(VerifyError) => Ok(OnDecided::Inert {
                    reason: InertReason::ProofInvalid,
                }),
                Ok(()) if V::UNLOCKS_SETTLEMENT => self
                    .apply
                    .apply_decided(value, deltas)
                    .map(OnDecided::Settled),
                Ok(()) => Ok(OnDecided::Inert {
                    reason: InertReason::ProofInvalid,
                }),
            },
        }
    }
}
