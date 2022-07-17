// Scheduler, and trait for .seconds(), .minutes(), etc.
use clokwerk::{AsyncScheduler, TimeUnits};

// Import week days and WeekDay
use starknet::accounts::SingleOwnerAccount;
use starknet::core::chain_id;
use starknet::core::types::FieldElement;
use starknet::signers::{LocalWallet, SigningKey};
use std::fs;
use std::time::Duration;

mod client_lib;

use std::time::{SystemTime, UNIX_EPOCH};

fn num_of_requests() -> u128 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    return since_the_epoch
        .as_millis()
        .checked_rem(1)
        .expect("error performing modulus on epoch");
}

async fn make_requests() {
    let provider = client_lib::starknet_nile_localhost();

    let private_key =
        fs::read_to_string("secrets.txt").expect("Something went wrong reading the file");

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        FieldElement::from_hex_be(&private_key).unwrap(),
    ));

    let account_contract_address =
        FieldElement::from_hex_be("a2b80a672ba14339997ccf71274f57463a902cd740f9d0f02786bc3b440864")
            .unwrap();

    let account = SingleOwnerAccount::new(
        provider.clone(),
        signer,
        account_contract_address,
        chain_id::TESTNET,
    );

    let dice_address = FieldElement::from_hex_be(
        "0544bcbeb6b0c974311d2e028ef8bf0a838020581588cf234e78550ff39497df",
    )
    .unwrap();

    for _ in 1..2 {
        client_lib::make_rng_request(account.clone(), dice_address).await
    }
}

#[tokio::main]
async fn main() {
    let mut scheduler = AsyncScheduler::new();
    scheduler.every(1.seconds()).run(|| async {
        make_requests().await;
    });

    tokio::spawn(async move {
        loop {
            print!("loop");
            make_requests().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
    .await
    .expect("task failed");
}
