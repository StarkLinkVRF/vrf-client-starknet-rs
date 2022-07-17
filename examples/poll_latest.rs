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

async fn poll_latest_block(block_number: Option<u64>) -> Option<u64> {
    let provider = client_lib::starknet_nile_localhost();

    let latest_block = client_lib::get_latest_block(provider).await;

    let mut is_new_block = true;

    print!(".");
    match block_number {
        Some(x) => is_new_block = latest_block.block_number.unwrap() != x,
        // The division was invalid
        None => println!("empty block number"),
    }

    if is_new_block == true {
        println!("{:#?}", latest_block);

        for tx_reciept in latest_block.transaction_receipts {
            for event in tx_reciept.events {}
        }
    }
    return latest_block.block_number;
}

#[tokio::main]
async fn main() {
    print!("hi");

    let mut block_number: Option<u64> = Option::None;
    tokio::spawn(async move {
        loop {
            block_number = poll_latest_block(block_number).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .expect("task failed");
}
