//! # Basic example
//!
//! This example shows a basic usage of the `vrf-rs` crate:
//!
//! 1. Instantiate the `ECVRF` by specifying the `CipherSuite`
//! 2. Generate a VRF proof by using the `prove()` function
//! 3. (Optional) Convert the VRF proof to a hash (e.g. to be used as pseudo-random value)
//! 4. Verify a VRF proof by using `verify()` function
use openssl::bn::BigNum;
use starknet::core::types::FieldElement;
use std::fs;
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;
mod utils;
fn main() {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let vrf_private_key = fs::read_to_string("secrets/local-vrf-secret.txt")
        .expect("Something went wrong reading the file");

    let secret_key = hex::decode(&vrf_private_key).unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();

    println!("Generated VRF public key: {}", hex::encode(&public_key));

    let alpha_hash = FieldElement::from_hex_be("268a9d47dde48af4b6e2c33932ed1c13adec25555abaa837c376af4ea2f8a94").unwrap();
    
    println!("alpha hash {:?} ", alpha_hash);
    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, alpha_hash).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();

    println!("Generated VRF proof: {}", hex::encode(&pi));

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(&public_key, &pi, alpha_hash);
    vrf.decode_proof(&pi);
    match beta {
        Ok(beta) => {
            println!("VRF proof is valid!\nHash output: {}", hex::encode(&beta));
            assert_eq!(hash, beta);
        }
        Err(e) => {
            println!("VRF proof is not valid: {}", e);
        }
    }
}
