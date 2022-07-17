// Scheduler, and trait for .seconds(), .minutes(), etc.
use clokwerk::{AsyncScheduler, TimeUnits};

// Import week days and WeekDay
use starknet::accounts::SingleOwnerAccount;
use starknet::core::chain_id;
use starknet::core::types::{BlockId, FieldElement};
use starknet::providers::Provider;
use starknet::signers::{LocalWallet, SigningKey};
use std::fs;
use std::time::Duration;

mod client_lib;
async fn respond_to_requests(block_number: Option<u64>) -> Option<u64> {
    let provider = client_lib::starknet_nile_localhost();
    let oracle_address = FieldElement::from_hex_be(
        "037e43c6bb2ea2cec7b7ed54d73cef9a44c74b653d7ca8c59d0546036ba26912",
    )
    .unwrap();

    let latest_block_number = provider
        .get_block(BlockId::Latest)
        .await
        .expect("error getting latest block")
        .block_number
        .expect("error getting black number");
    let mut block_num = 1;

    match block_number {
        Some(x) => block_num = x,
        // The division was invalid
        None => block_num = latest_block_number,
    }

    let mut all_requests: Vec<FieldElement> = Vec::new();

    println!(
        "Getting requests from block #{} to #{}",
        block_num, latest_block_number
    );
    for n in block_num..latest_block_number {
        println!("Querying provider for block number #{}", n);
        let mut request_indexes =
            client_lib::get_rng_request_events(provider.clone(), oracle_address, block_num).await;

        if request_indexes.len() == 0 {
            println!("Found no request for block number #{}", n);
        } else {
            println!(
                "Found indexes {:?} for block number #{}",
                request_indexes, n
            );
        }

        all_requests.append(&mut request_indexes);
    }

    if all_requests.len() == 0 {
        println!(
            " No requests found, #{} to #{} \n Returning",
            block_num, latest_block_number
        );
        return Some(latest_block_number);
    }

    println!("found request indexes {:?}", all_requests);
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

    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();

    client_lib::resolve_rng_requests(account, all_requests.clone(), oracle_address, secret_key)
        .await;

    let dice_address = FieldElement::from_hex_be(
        "0544bcbeb6b0c974311d2e028ef8bf0a838020581588cf234e78550ff39497df",
    )
    .unwrap();

    for index in all_requests.clone() {
        client_lib::get_roll_result(dice_address.clone(), index).await
    }

    return Some(latest_block_number);
}

#[tokio::main]
async fn main() {
    let mut block_number: Option<u64> = Option::None;
    tokio::spawn(async move {
        loop {
            println!("looking at block {:?}", block_number);
            block_number = respond_to_requests(block_number).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("task failed");
}
