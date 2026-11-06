//! Suite-tagged signer/verifier for [`PlxContext`] (Phase 7, ADR 0030):
//! classical Ed25519 or hybrid Ed25519 + ML-DSA-65, with a minimum-suite
//! policy so a downgraded (weaker-suite) vote or proposal is rejected.

use async_trait::async_trait;
use bytes::Bytes;
use malachitebft_core_types::{
    NilOrVal, SignedExtension, SignedMessage, SignedProposal, SignedVote, ValidatorProof,
    VoteExtensionScope,
};
use malachitebft_signing::{Error, Signer, VerificationResult, Verifier};
use crypto_suite::{
    SuitePolicy, SuitePublicKey as PublicKey, SuiteSignature as Signature, SuiteSigningKey,
};

use super::context::{PlxContext, Vote};

const VOTE_EXTENSION_DOMAIN: &[u8] = b"plx/cons/vote-extension/v1\0";

/// Per-message signing contexts: a vote signature never verifies as a proposal.
const CTX_VOTE: &[u8] = b"plx/cons/vote";
const CTX_PROPOSAL: &[u8] = b"plx/cons/proposal";
const CTX_EXTENSION: &[u8] = b"plx/cons/vote-extension";
const CTX_PROOF: &[u8] = b"plx/cons/validator-proof";

fn vote_extension_sign_bytes(scope: &VoteExtensionScope<PlxContext>, extension: &Bytes) -> Vec<u8> {
    let precommit = Vote::new_precommit(
        scope.height,
        scope.round,
        NilOrVal::Val(scope.value_id),
        scope.validator_address,
    );
    let precommit_bytes = precommit.to_sign_bytes();
    let mut buf = Vec::new();
    buf.extend_from_slice(VOTE_EXTENSION_DOMAIN);
    buf.extend_from_slice(&(precommit_bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(&precommit_bytes);
    buf.extend_from_slice(&(extension.len() as u64).to_be_bytes());
    buf.extend_from_slice(extension);
    buf
}

/// Verifies suite signatures; anything below `policy.min` is a downgrade.
#[derive(Debug, Clone, Copy)]
pub struct PlxVerifier {
    policy: SuitePolicy,
}

impl PlxVerifier {
    pub fn new(policy: SuitePolicy) -> Self {
        Self { policy }
    }

    fn verify(&self, ctx: &[u8], data: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
        crypto_suite::verify(self.policy, public_key, ctx, data, signature).is_ok()
    }
}

#[async_trait]
impl Verifier<PlxContext> for PlxVerifier {
    async fn verify_signed_vote(
        &self,
        vote: &Vote,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(self.verify(
            CTX_VOTE,
            &vote.to_sign_bytes(),
            signature,
            public_key,
        )))
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &super::context::Proposal,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ok(VerificationResult::from_bool(self.verify(
            CTX_PROPOSAL,
            &proposal.to_sign_bytes(),
            signature,
            public_key,
        )))
    }

    async fn verify_signed_vote_extension(
        &self,
        scope: &VoteExtensionScope<PlxContext>,
        extension: &Bytes,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        let preimage = vote_extension_sign_bytes(scope, extension);
        Ok(VerificationResult::from_bool(self.verify(
            CTX_EXTENSION,
            &preimage,
            signature,
            public_key,
        )))
    }

    async fn verify_validator_proof(
        &self,
        proof: &ValidatorProof<PlxContext>,
    ) -> Result<VerificationResult, Error> {
        let public_key = proof.decoded_public_key().map_err(|e| {
            Error::from_source(format!("invalid public key in validator proof: {e}"))
        })?;
        // Classical floor on purpose (ADR 0030): a proof only labels a libp2p
        // peer for scoring; votes and proposals stay under `policy`. Rejecting
        // a downgraded peer's proof makes Malachite drop and redial it, and that
        // churn also cut honest links (2 / 13 stalls at a 3-of-4 quorum).
        let ok = crypto_suite::verify(
            SuitePolicy::CLASSICAL,
            &public_key,
            CTX_PROOF,
            &proof.preimage(),
            &proof.signature,
        )
        .is_ok();
        Ok(VerificationResult::from_bool(ok))
    }
}

#[derive(Debug)]
pub struct PlxSigner {
    key: SuiteSigningKey,
    verifier: PlxVerifier,
}

impl PlxSigner {
    pub fn new(key: SuiteSigningKey, policy: SuitePolicy) -> Self {
        Self {
            key,
            verifier: PlxVerifier::new(policy),
        }
    }

    pub fn sign(&self, ctx: &[u8], data: &[u8]) -> Signature {
        self.key.sign(ctx, data)
    }
}

#[async_trait]
impl Verifier<PlxContext> for PlxSigner {
    async fn verify_signed_vote(
        &self,
        vote: &Vote,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        self.verifier
            .verify_signed_vote(vote, signature, public_key)
            .await
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &super::context::Proposal,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        self.verifier
            .verify_signed_proposal(proposal, signature, public_key)
            .await
    }

    async fn verify_signed_vote_extension(
        &self,
        scope: &VoteExtensionScope<PlxContext>,
        extension: &Bytes,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        self.verifier
            .verify_signed_vote_extension(scope, extension, signature, public_key)
            .await
    }

    async fn verify_validator_proof(
        &self,
        proof: &ValidatorProof<PlxContext>,
    ) -> Result<VerificationResult, Error> {
        self.verifier.verify_validator_proof(proof).await
    }
}

#[async_trait]
impl Signer<PlxContext> for PlxSigner {
    async fn sign_vote(&self, vote: Vote) -> Result<SignedVote<PlxContext>, Error> {
        let signature = self.sign(CTX_VOTE, &vote.to_sign_bytes());
        Ok(SignedVote::new(vote, signature))
    }

    async fn sign_proposal(
        &self,
        proposal: super::context::Proposal,
    ) -> Result<SignedProposal<PlxContext>, Error> {
        let signature = self.sign(CTX_PROPOSAL, &proposal.to_sign_bytes());
        Ok(SignedProposal::new(proposal, signature))
    }

    async fn sign_vote_extension(
        &self,
        scope: VoteExtensionScope<PlxContext>,
        extension: Bytes,
    ) -> Result<SignedExtension<PlxContext>, Error> {
        let preimage = vote_extension_sign_bytes(&scope, &extension);
        let signature = self.sign(CTX_EXTENSION, &preimage);
        Ok(SignedMessage::new(extension, signature))
    }

    async fn sign_validator_proof(
        &self,
        public_key: Vec<u8>,
        peer_id: Vec<u8>,
    ) -> Result<ValidatorProof<PlxContext>, Error> {
        let preimage = ValidatorProof::<PlxContext>::signing_bytes(&public_key, &peer_id);
        let signature = self.sign(CTX_PROOF, &preimage);
        Ok(ValidatorProof::new(public_key, peer_id, signature))
    }
}
