//! Signed orders (ADR 0033). An account is its suite key: `OwnerId =
//! SHA-256("plx/account/v1" ‖ encoded suite public key)`, the same model as
//! validator addresses, so a hybrid (Ed25519 + ML-DSA-65) account needs no
//! registry and no migration of the id format.
//!
//! A `Place` or `Cancel` carries `(public key, signature)` over its canonical
//! bytes (`AdvanceHeight` is never admitted from clients). Validators check it at admission (local submit and gossip ingest);
//! `I`, `F` and `π` are unchanged. Authorization is attested by the validators
//! (and the hybrid finality certificate, ADR 0031), not re-proven in the zkVM.

use crypto_suite::{verify, SigError, SuitePolicy, SuitePublicKey, SuiteSignature, SuiteSigningKey};
use protocol_types::{CanonicalEncode, Input, OwnerId};
use sha2::{Digest as _, Sha256};

pub const CTX_ORDER: &[u8] = b"plx/order/v1";
const ACCOUNT_DOMAIN: &[u8] = b"plx/account/v1";

/// The account id of a suite key.
pub fn owner_of(pk: &SuitePublicKey) -> OwnerId {
    OwnerId(Sha256::new().chain_update(ACCOUNT_DOMAIN).chain_update(pk.encode()).finalize().into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderAuth {
    pub pk: SuitePublicKey,
    pub sig: SuiteSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OrderAuthError {
    #[error("order needs a signature")]
    Unsigned,
    #[error("key does not hash to the order's owner")]
    WrongOwner,
    #[error("signature: {0}")]
    Signature(SigError),
    /// `AdvanceHeight` is a protocol input; clients and gossip may not send it.
    #[error("system input from a client")]
    SystemInput,
}

/// Inputs only the protocol may insert. Admitting a client's
/// `AdvanceHeight { to: 10⁹ }` would expire every resting order with an
/// expiry and wedge later height advances (`HeightNotMonotonic`).
pub fn is_system_input(input: &Input) -> bool {
    matches!(input, Input::AdvanceHeight { .. })
}

fn signer_of(input: &Input) -> Option<OwnerId> {
    match input {
        Input::Place(o) => Some(o.owner),
        Input::Cancel { owner, .. } => Some(*owner),
        // System input: no account; never admitted from clients.
        Input::AdvanceHeight { .. } => None,
    }
}

pub fn sign_order(key: &SuiteSigningKey, input: &Input) -> OrderAuth {
    OrderAuth {
        pk: key.public(),
        sig: key.sign(CTX_ORDER, &input.encode_vec()),
    }
}

/// Admission check: account inputs must be signed by their owner's key under
/// `policy`; system inputs are refused.
pub fn check_order(policy: SuitePolicy, input: &Input, auth: Option<&OrderAuth>) -> Result<(), OrderAuthError> {
    let Some(owner) = signer_of(input) else {
        return Err(OrderAuthError::SystemInput);
    };
    let auth = auth.ok_or(OrderAuthError::Unsigned)?;
    if owner_of(&auth.pk) != owner {
        return Err(OrderAuthError::WrongOwner);
    }
    verify(policy, &auth.pk, CTX_ORDER, &input.encode_vec(), &auth.sig).map_err(OrderAuthError::Signature)
}

impl OrderAuth {
    /// `u32 len ‖ pk ‖ u32 len ‖ sig`.
    pub fn encode(&self) -> Vec<u8> {
        let (pk, sig) = (self.pk.encode(), self.sig.encode());
        let mut out = Vec::with_capacity(8 + pk.len() + sig.len());
        for part in [&pk, &sig] {
            out.extend_from_slice(&(part.len() as u32).to_le_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// Returns the auth and the bytes consumed.
    pub fn decode(b: &[u8]) -> Option<(Self, usize)> {
        let mut at = 0;
        let mut part = || -> Option<&[u8]> {
            let n = u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize;
            let p = b.get(at + 4..at + 4 + n)?;
            at += 4 + n;
            Some(p)
        };
        let pk = SuitePublicKey::decode(part()?)?;
        let sig = SuiteSignature::decode(part()?)?;
        Some((Self { pk, sig }, at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clob::testutil::limit;
    use protocol_types::{CryptoSuiteId, Order, Side};

    fn account(suite: CryptoSuiteId, seed: u8) -> (SuiteSigningKey, OwnerId) {
        let k = SuiteSigningKey::from_seed(suite, [seed; 32]);
        let owner = owner_of(&k.public());
        (k, owner)
    }

    fn place_by(owner: OwnerId, nonce: u64) -> Input {
        let Input::Place(mut o) = Input::Place(limit(1, 1, Side::Buy, 5, 10, nonce)) else { unreachable!() };
        o.owner = owner;
        Input::Place(Order { ..o })
    }

    #[test]
    fn signed_orders_verify_and_round_trip() {
        for suite in [CryptoSuiteId::ClassicalV0, CryptoSuiteId::HybridV1] {
            let (k, owner) = account(suite, 3);
            let input = place_by(owner, 1);
            let auth = sign_order(&k, &input);
            assert_eq!(check_order(SuitePolicy::CLASSICAL, &input, Some(&auth)), Ok(()));
            let enc = auth.encode();
            assert_eq!(OrderAuth::decode(&enc), Some((auth, enc.len())));
        }
    }

    #[test]
    fn unsigned_wrong_owner_tampered_and_downgraded_rejected() {
        let (k, owner) = account(CryptoSuiteId::HybridV1, 3);
        let input = place_by(owner, 1);
        assert_eq!(check_order(SuitePolicy::HYBRID, &input, None), Err(OrderAuthError::Unsigned));
        // Someone else's key, valid signature: not the owner.
        let (other, _) = account(CryptoSuiteId::HybridV1, 4);
        assert_eq!(
            check_order(SuitePolicy::HYBRID, &input, Some(&sign_order(&other, &input))),
            Err(OrderAuthError::WrongOwner)
        );
        // Signature for a different order (nonce changed).
        let auth = sign_order(&k, &place_by(owner, 2));
        assert!(matches!(check_order(SuitePolicy::HYBRID, &input, Some(&auth)), Err(OrderAuthError::Signature(_))));
        // A classical account under a hybrid policy.
        let (c, c_owner) = account(CryptoSuiteId::ClassicalV0, 5);
        let ci = place_by(c_owner, 1);
        assert_eq!(
            check_order(SuitePolicy::HYBRID, &ci, Some(&sign_order(&c, &ci))),
            Err(OrderAuthError::Signature(SigError::Downgrade))
        );
        // The same Ed25519 key as a hybrid account is a different owner: an
        // account cannot be downgraded by re-labelling its key.
        assert_ne!(owner_of(&k.public()), owner_of(&k.public().classical()));
        // System inputs are refused from clients, signed or not.
        let adv = Input::AdvanceHeight { to: protocol_types::Height(9) };
        assert_eq!(check_order(SuitePolicy::HYBRID, &adv, None), Err(OrderAuthError::SystemInput));
    }
}
