//! Malachite [`SigningScheme`] over suite-tagged keys and signatures
//! (Phase 7, ADR 0030): classical Ed25519 or hybrid Ed25519 + ML-DSA-65.

use crypto_suite::{SuitePublicKey, SuiteSignature, SuiteSigningKey};
use malachitebft_core_types::SigningScheme;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlxSuite;

impl SigningScheme for PlxSuite {
    type DecodingError = String;
    type Signature = SuiteSignature;
    type PublicKey = SuitePublicKey;
    type PrivateKey = SuiteSigningKey;

    fn decode_signature(bytes: &[u8]) -> Result<SuiteSignature, String> {
        SuiteSignature::decode(bytes).ok_or_else(|| "bad suite signature".into())
    }

    fn encode_signature(signature: &SuiteSignature) -> Vec<u8> {
        signature.encode()
    }

    fn decode_public_key(bytes: &[u8]) -> Result<SuitePublicKey, String> {
        SuitePublicKey::decode(bytes).ok_or_else(|| "bad suite public key".into())
    }

    fn encode_public_key(public_key: &SuitePublicKey) -> Vec<u8> {
        public_key.encode()
    }
}
