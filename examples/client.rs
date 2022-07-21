// Scheduler, and trait for .seconds(), .minutes(), etc.
use clokwerk::{AsyncScheduler, TimeUnits};

use serde::__private::de::IdentifierDeserializer;
// Import week days and WeekDay
use starknet::accounts::SingleOwnerAccount;
use starknet::core::chain_id;
use starknet::core::types::{BlockId, FieldElement};
use starknet::providers::{Provider, SequencerGatewayProvider};
use starknet::signers::{LocalWallet, SigningKey};
use std::env;
use std::fs;
use std::time::Duration;

mod client_lib;

const ORACLE_ADDRESS_STRING: &str =
    "0540d7a06267f177f84a323d2b4b92b8ac259f97eb2c398b29da888fbb3a30b2";
const DICE_ADDRESS_STRING: &str =
    "04cc9e47b19af7a008ae2eb4d420ce7e215e3ccdf8f6cd99db72b97f933a516a";

const WALLET_ADDRESS_STRING: &str =
    "7b1fa023a35b606f3790ae70a3ed1172238be1e7ea9e740bb66255747118f6a";

async fn respond_to_requests(block_number: Option<u64>) -> Option<u64> {
    let args: Vec<String> = env::args().collect();

    println!("{:?}", args);
    let network = args[1].clone();

    let mut provider = client_lib::starknet_nile_localhost();
    if network.eq(&String::from("goerli")) {
        provider = SequencerGatewayProvider::starknet_alpha_goerli();
    } else if network.eq(&String::from("local")) {
        provider = client_lib::starknet_nile_localhost();
    } else if network.eq(&String::from("mainnet")) {
        provider = SequencerGatewayProvider::starknet_alpha_mainnet()
    } else {
        panic!("no enviornment find, use goerli, local")
    }

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

    let oracle_address = FieldElement::from_hex_be(ORACLE_ADDRESS_STRING).unwrap();

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

    let mut wallet_private_key = "secrets/".to_owned();
    wallet_private_key.push_str(&network);
    wallet_private_key.push_str("-wallet-secret.txt");

    let private_key =
        fs::read_to_string(wallet_private_key).expect("Something went wrong reading the file");

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        FieldElement::from_hex_be(&private_key).unwrap(),
    ));

    let account_contract_address = FieldElement::from_hex_be(WALLET_ADDRESS_STRING).unwrap();

    let mut chain_id = chain_id::TESTNET;
    if network.eq("mainnet") {
        chain_id = chain_id::MAINNET
    }

    let account =
        SingleOwnerAccount::new(provider.clone(), signer, account_contract_address, chain_id);

    let vrf_private_key = fs::read_to_string("secrets/vrf-secret.txt")
        .expect("Something went wrong reading the file");

    let secret_key = hex::decode(&vrf_private_key).unwrap();

    client_lib::resolve_rng_requests(account, all_requests.clone(), oracle_address, secret_key)
        .await;

    let dice_address = FieldElement::from_hex_be(DICE_ADDRESS_STRING).unwrap();

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
