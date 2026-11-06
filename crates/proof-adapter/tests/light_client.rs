//! Light-client verifier object: Plonky3 tiny-`F` STARK as `VerifyFragment`.
//!
//! Not height `π`. Not Groth16. Not a CLOB apply license. `SettlementGate`
//! takes [`HeightStatement`], which this verifier cannot satisfy.

use proof_adapter::{Plonky3TinyVerifier, VerifyFragment};
use proof_plonky3::{prove_tiny_with, FriClass};
use protocol_types::{Price, Qty};
use tiny_f::{TinyInstance, TinyStatement};

fn fill_stmt() -> TinyStatement {
    TinyStatement::prove_native(TinyInstance {
        maker_qty: Qty(10),
        taker_qty: Qty(7),
        price: Price(90),
    })
    .unwrap()
}

fn other_stmt() -> TinyStatement {
    TinyStatement::prove_native(TinyInstance {
        maker_qty: Qty(10),
        taker_qty: Qty(10),
        price: Price(90),
    })
    .unwrap()
}

#[test]
fn matching_fragment_verifies() {
    let stmt = fill_stmt();
    let proof = prove_tiny_with(stmt, FriClass::Test).unwrap();
    Plonky3TinyVerifier::test()
        .verify(&stmt, &proof.bytes)
        .unwrap();
}

#[test]
fn different_statement_rejected() {
    let stmt = fill_stmt();
    let proof = prove_tiny_with(stmt, FriClass::Test).unwrap();
    assert!(Plonky3TinyVerifier::test()
        .verify(&other_stmt(), &proof.bytes)
        .is_err());
}

#[test]
fn garbage_rejected() {
    let stmt = fill_stmt();
    assert!(Plonky3TinyVerifier::test()
        .verify(&stmt, b"not-a-stark")
        .is_err());
}

#[test]
fn groth16_shaped_bytes_rejected() {
    let stmt = fill_stmt();
    let fake = vec![0u8; 256];
    assert!(Plonky3TinyVerifier::test().verify(&stmt, &fake).is_err());
    assert!(Plonky3TinyVerifier::prod().verify(&stmt, &fake).is_err());
}

#[test]
fn test_fri_rejected_by_prod_verifier() {
    let stmt = fill_stmt();
    let proof = prove_tiny_with(stmt, FriClass::Test).unwrap();
    assert!(Plonky3TinyVerifier::prod()
        .verify(&stmt, &proof.bytes)
        .is_err());
}

#[test]
fn fragment_verifier_is_not_height_pi() {
    fn assert_fragment<V: VerifyFragment>(_: &V) {}
    assert_fragment(&Plonky3TinyVerifier::test());
}

#[cfg(not(debug_assertions))]
#[test]
fn light_client_prod_verify_through_object() {
    let stmt = fill_stmt();
    let t0 = std::time::Instant::now();
    let proof = prove_tiny_with(stmt, FriClass::Prod).unwrap();
    let prove_ms = t0.elapsed().as_millis();
    let v = Plonky3TinyVerifier::prod();
    let t1 = std::time::Instant::now();
    v.verify(&stmt, &proof.bytes).unwrap();
    let verify_ms = t1.elapsed().as_millis();
    assert!(proof.bytes.len() > 10_000);
    eprintln!(
        "light-client Plonky3TinyVerifier prod: prove {} ms, verify {} ms, {} bytes",
        prove_ms,
        verify_ms,
        proof.bytes.len()
    );
}
