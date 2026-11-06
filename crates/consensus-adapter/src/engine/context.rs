//! Malachite `Context` whose `Value` is the M4a public bundle (ADR 0009).
//!
//! `TestContext` cannot be reused: its `Value`/`ValueId` are `u64`.

use core::fmt;
use std::sync::Arc;

use bytes::Bytes;
use commitments::{value_id, Digest};
use malachitebft_core_types::{
    Context, LinearTimeouts, NilOrVal, Round, SignedExtension, ValidatorSet as _, VoteType,
};
use crypto_suite::SuitePublicKey as PublicKey;

use super::scheme::PlxSuite;
use protocol_types::ConsensusValue;

pub type VotingPower = u64;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ConsHeight(u64);

impl ConsHeight {
    pub const fn new(h: u64) -> Self {
        Self(h)
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn protocol(self) -> protocol_types::Height {
        protocol_types::Height(self.0)
    }
}

impl fmt::Display for ConsHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for ConsHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Height({})", self.0)
    }
}

impl malachitebft_core_types::Height for ConsHeight {
    const ZERO: Self = Self(0);
    const INITIAL: Self = Self(1);

    fn increment_by(&self, n: u64) -> Self {
        Self(self.0 + n)
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        self.0.checked_sub(n).map(Self)
    }

    fn as_u64(&self) -> u64 {
        self.0
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 20]);

impl Address {
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Hash of the suite-tagged key (`post-quantum.md`, Q-CRY-4): the same
    /// Ed25519 key under another suite is another address.
    pub fn from_public_key(pk: &PublicKey) -> Self {
        let hash = blake3::hash(&pk.encode());
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash.as_bytes()[..20]);
        Self(out)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

impl malachitebft_core_types::Address for Address {}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueId(pub Digest);

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlxValue(pub ConsensusValue);

impl PlxValue {
    pub fn id(&self) -> ValueId {
        ValueId(value_id(&self.0))
    }
}

impl malachitebft_core_types::Value for PlxValue {
    type Id = ValueId;

    fn id(&self) -> ValueId {
        self.id()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalPart {
    pub height: ConsHeight,
    pub round: Round,
    pub proposer: Address,
    pub value: PlxValue,
}

impl malachitebft_core_types::ProposalPart<PlxContext> for ProposalPart {
    fn is_first(&self) -> bool {
        true
    }

    fn is_last(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub height: ConsHeight,
    pub round: Round,
    pub value: PlxValue,
    pub pol_round: Round,
    pub validator_address: Address,
}

impl Proposal {
    pub fn new(
        height: ConsHeight,
        round: Round,
        value: PlxValue,
        pol_round: Round,
        validator_address: Address,
    ) -> Self {
        Self {
            height,
            round,
            value,
            pol_round,
            validator_address,
        }
    }

    pub fn to_sign_bytes(&self) -> Bytes {
        crate::engine::codec::encode_proposal(self).into()
    }
}

impl malachitebft_core_types::Proposal<PlxContext> for Proposal {
    fn height(&self) -> ConsHeight {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &PlxValue {
        &self.value
    }

    fn take_value(self) -> PlxValue {
        self.value
    }

    fn pol_round(&self) -> Round {
        self.pol_round
    }

    fn validator_address(&self) -> &Address {
        &self.validator_address
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    pub typ: VoteType,
    pub height: ConsHeight,
    pub round: Round,
    pub value: NilOrVal<ValueId>,
    pub validator_address: Address,
    pub extension: Option<SignedExtension<PlxContext>>,
}

impl Vote {
    pub fn new_prevote(
        height: ConsHeight,
        round: Round,
        value: NilOrVal<ValueId>,
        validator_address: Address,
    ) -> Self {
        Self {
            typ: VoteType::Prevote,
            height,
            round,
            value,
            validator_address,
            extension: None,
        }
    }

    pub fn new_precommit(
        height: ConsHeight,
        round: Round,
        value: NilOrVal<ValueId>,
        validator_address: Address,
    ) -> Self {
        Self {
            typ: VoteType::Precommit,
            height,
            round,
            value,
            validator_address,
            extension: None,
        }
    }

    pub fn to_sign_bytes(&self) -> Bytes {
        let stripped = Self {
            extension: None,
            ..self.clone()
        };
        crate::engine::codec::encode_vote(&stripped).into()
    }
}

impl malachitebft_core_types::Vote<PlxContext> for Vote {
    fn height(&self) -> ConsHeight {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &NilOrVal<ValueId> {
        &self.value
    }

    fn take_value(self) -> NilOrVal<ValueId> {
        self.value
    }

    fn vote_type(&self) -> VoteType {
        self.typ
    }

    fn validator_address(&self) -> &Address {
        &self.validator_address
    }

    fn extension(&self) -> Option<&SignedExtension<PlxContext>> {
        self.extension.as_ref()
    }

    fn take_extension(&mut self) -> Option<SignedExtension<PlxContext>> {
        self.extension.take()
    }

    fn extend(self, extension: SignedExtension<PlxContext>) -> Self {
        Self {
            extension: Some(extension),
            ..self
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub address: Address,
    pub public_key: PublicKey,
    pub voting_power: VotingPower,
}

impl Validator {
    pub fn new(public_key: PublicKey, voting_power: VotingPower) -> Self {
        Self {
            address: Address::from_public_key(&public_key),
            public_key,
            voting_power,
        }
    }
}

impl PartialOrd for Validator {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Validator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl malachitebft_core_types::Validator<PlxContext> for Validator {
    fn address(&self) -> &Address {
        &self.address
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn voting_power(&self) -> VotingPower {
        self.voting_power
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    pub validators: Arc<Vec<Validator>>,
}

impl ValidatorSet {
    pub fn new(validators: impl IntoIterator<Item = Validator>) -> Self {
        let validators: Vec<_> = validators.into_iter().collect();
        assert!(!validators.is_empty());
        Self {
            validators: Arc::new(validators),
        }
    }

    pub fn get_by_index(&self, index: usize) -> Option<&Validator> {
        self.validators.get(index)
    }
}

impl malachitebft_core_types::ValidatorSet<PlxContext> for ValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }

    fn total_voting_power(&self) -> VotingPower {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    fn get_by_address(&self, address: &Address) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    fn get_by_index(&self, index: usize) -> Option<&Validator> {
        self.validators.get(index)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PlxContext;

impl PlxContext {
    pub fn select_proposer_index(
        validator_set: &ValidatorSet,
        height: ConsHeight,
        round: Round,
    ) -> usize {
        let n = validator_set.count();
        assert!(n > 0);
        assert!(round != Round::Nil && round.as_i64() >= 0);
        let h = height.as_u64() as usize;
        let r = round.as_i64() as usize;
        (h - 1 + r) % n
    }
}

impl Context for PlxContext {
    type Address = Address;
    type Height = ConsHeight;
    type ProposalPart = ProposalPart;
    type Proposal = Proposal;
    type Validator = Validator;
    type ValidatorSet = ValidatorSet;
    type Timeouts = LinearTimeouts;
    type Value = PlxValue;
    type Vote = Vote;
    type Extension = Bytes;
    type SigningScheme = PlxSuite;

    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        let i = Self::select_proposer_index(validator_set, height, round);
        validator_set
            .get_by_index(i)
            .expect("proposer index in range")
    }

    fn new_proposal(
        &self,
        height: ConsHeight,
        round: Round,
        value: PlxValue,
        pol_round: Round,
        address: Address,
    ) -> Proposal {
        Proposal::new(height, round, value, pol_round, address)
    }

    fn new_prevote(
        &self,
        height: ConsHeight,
        round: Round,
        value_id: NilOrVal<ValueId>,
        address: Address,
    ) -> Vote {
        Vote::new_prevote(height, round, value_id, address)
    }

    fn new_precommit(
        &self,
        height: ConsHeight,
        round: Round,
        value_id: NilOrVal<ValueId>,
        address: Address,
    ) -> Vote {
        Vote::new_precommit(height, round, value_id, address)
    }
}
