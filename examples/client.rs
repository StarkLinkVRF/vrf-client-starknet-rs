use client_lib::starknet_nile_localhost;
// Scheduler, and trait for .seconds(), .minutes(), etc.
use clokwerk::{AsyncScheduler, TimeUnits};

// Import week days and WeekDay
use clokwerk::Interval::*;
use starknet::accounts::SingleOwnerAccount;
use starknet::core::chain_id;
use starknet::core::types::FieldElement;
use starknet::signers::{LocalWallet, SigningKey};
use std::time::Duration;
use std::{fs, thread};

mod client_lib;

async fn respond_to_requests() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let private_key =
        fs::read_to_string("secrets.txt").expect("Something went wrong reading the file");
    let provider = starknet_nile_localhost();

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        FieldElement::from_hex_be(&private_key).unwrap(),
    ));

    let account_contract_address = FieldElement::from_hex_be(
        "4077a895eda64b37f4ff7bf9beb16b487c9f9535662fcde096b747fa75643dc",
    )
    .unwrap();

    let account = SingleOwnerAccount::new(
        provider.clone(),
        signer,
        account_contract_address,
        chain_id::TESTNET,
    );

    let indexes: Vec<FieldElement> = Vec::new();
    let oracle_address = FieldElement::from_hex_be(
        "04102e75c500fe57a7ae4825c56500a0395fccab45ad7b5ebdd1ab1545ac7f0b",
    )
    .unwrap();

    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();

    client_lib::resolve_rng_requests(
        provider.clone(),
        account,
        indexes,
        oracle_address,
        secret_key,
    )
    .await
}
fn main() {
    let mut scheduler = AsyncScheduler::new();
    scheduler.every(60.seconds()).run(|| async {
        respond_to_requests();
    });

    tokio::spawn(async move {
        loop {
            scheduler.run_pending().await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}
