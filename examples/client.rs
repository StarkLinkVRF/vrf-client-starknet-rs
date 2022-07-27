// Scheduler, and trait for .seconds(), .minutes(), etc.

// Import week days and WeekDay
use starknet::accounts::SingleOwnerAccount;
use starknet::core::chain_id;
use starknet::core::types::{BlockId, FieldElement, TransactionStatus};
use starknet::providers::{Provider, SequencerGatewayProvider};
use starknet::signers::{LocalWallet, SigningKey};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::time::Duration;

mod client_lib;

#[derive(Clone)]
struct AccountInstance {
    private_key: FieldElement,
    account_address: FieldElement,
    current_tx: Option<FieldElement>,
}

const ORACLE_ADDRESS_STRING: &str =
    "0746077cd8eb9cce682daf051bb1fec88f3ba7c6e75e2413bb09a210ab9a2514";

async fn fetch_new_requests(
    block_number: Option<u64>,
    provider: SequencerGatewayProvider,
) -> (Option<u64>, Option<Vec<FieldElement>>) {
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

    if block_num == latest_block_number {
        return (Some(block_num), None);
    }
    let mut all_requests: Vec<FieldElement> = Vec::new();

    println!(
        "Getting requests from block #{} to #{}",
        block_num, latest_block_number
    );

    let oracle_address = FieldElement::from_hex_be(ORACLE_ADDRESS_STRING).unwrap();

    for n in block_num + 1..=latest_block_number {
        println!("Querying provider for block number #{}", n);
        let mut request_indexes =
            client_lib::get_rng_request_events(provider.clone(), oracle_address, n).await;

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
        return (Some(latest_block_number), None);
    }

    return (Some(latest_block_number), Some(all_requests));
}

async fn respond_to_request(
    account: AccountInstance,
    provider: SequencerGatewayProvider,
    network: String,
    request: FieldElement,
) -> Option<FieldElement> {
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(account.private_key));

    let mut chain_id = chain_id::TESTNET;
    if network.eq("mainnet") {
        chain_id = chain_id::MAINNET
    }

    let account =
        SingleOwnerAccount::new(provider.clone(), signer, account.account_address, chain_id);

    let vrf_private_key = fs::read_to_string("secrets/vrf-secret.txt")
        .expect("Something went wrong reading the file");

    let secret_key = hex::decode(&vrf_private_key).unwrap();

    let oracle_address = FieldElement::from_hex_be(ORACLE_ADDRESS_STRING).unwrap();

    let mut all_requests = Vec::new();
    all_requests.push(request);
    let tx_hash =
        client_lib::resolve_rng_requests(account, all_requests.clone(), oracle_address, secret_key)
            .await;

    return tx_hash;
}

async fn respond_to_requests(
    mut requests: Vec<FieldElement>,
    accounts: Vec<AccountInstance>,
    provider: SequencerGatewayProvider,
    network: String,
) -> (Vec<FieldElement>, Vec<AccountInstance>) {
    if requests.len() == 0 {
        return (requests, accounts);
    }

    let mut fresh_account_instances = Vec::new();
    for account in accounts {
        if requests.len() == 0 {
            fresh_account_instances.push(account.clone());
            continue;
        }

        let mut tx_status = TransactionStatus::Pending;
        match account.current_tx {
            Some(tx) => {
                let get_tx_status_req = provider.get_transaction_status(tx).await;

                match get_tx_status_req {
                    Ok(status) => tx_status = status.status,
                    Err(e) => {
                        print!("{}", e)
                    }
                }
            }
            None => tx_status = TransactionStatus::AcceptedOnL1,
        }

        if tx_status != TransactionStatus::Pending
            && tx_status != TransactionStatus::Received
            && tx_status != TransactionStatus::NotReceived
        {
            let request = requests.pop();

            match request {
                Some(req) => {
                    let tx_hash =
                        respond_to_request(account.clone(), provider.clone(), network.clone(), req)
                            .await;

                    fresh_account_instances.push(AccountInstance {
                        private_key: account.private_key,
                        account_address: account.account_address,
                        current_tx: tx_hash,
                    })
                }
                None => {}
            }
        } else {
            fresh_account_instances.push(account.clone())
        }
    }

    return (requests, fresh_account_instances);
}

async fn get_provider(network: String) -> SequencerGatewayProvider {
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
    return provider;
}

async fn assemble_account_instances(network: String) -> Vec<AccountInstance> {
    let mut account_private_key_location = "secrets/".to_owned();
    account_private_key_location.push_str(&network);
    account_private_key_location.push_str("-wallet-secret.txt");

    let f = File::open(account_private_key_location).unwrap();
    let reader = BufReader::new(f);

    let mut available_accounts: Vec<FieldElement> = Vec::new();
    for available_account in reader.lines() {
        available_accounts.push(FieldElement::from_hex_be(&available_account.unwrap()).unwrap());
    }

    let mut account_address_location = "secrets/".to_owned();
    account_address_location.push_str(&network);
    account_address_location.push_str("-wallet-address.txt");

    let f = File::open(account_address_location).unwrap();
    let reader = BufReader::new(f);

    let mut account_addresses: Vec<FieldElement> = Vec::new();
    for address in reader.lines() {
        account_addresses.push(FieldElement::from_hex_be(&address.unwrap()).unwrap());
    }

    if available_accounts.len() != account_addresses.len() {
        panic!("each private key needs a corresponding address")
    }
    let mut account_instances: Vec<AccountInstance> = Vec::new();

    for i in 0..available_accounts.len() {
        let instance = AccountInstance {
            private_key: available_accounts[i],
            account_address: account_addresses[i],
            current_tx: None,
        };
        account_instances.push(instance);
    }

    return account_instances;
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let network = String::from("goerli");

    let provider = get_provider(network.clone()).await;

    let mut block_number: Option<u64> = Option::None;

    let mut account_instances = assemble_account_instances(network.clone()).await;

    let mut request_pool: Vec<FieldElement> = Vec::new();
    tokio::spawn(async move {
        loop {
            println!("looking at block {:?}", block_number);
            let (latest_block_number, new_requests) =
                fetch_new_requests(block_number, provider.clone()).await;

            block_number = latest_block_number;
            match new_requests {
                Some(mut reqs) => request_pool.append(&mut reqs),
                None => {}
            }

            let (updated_request_pool, fresh_instances) = respond_to_requests(
                request_pool.clone(),
                account_instances.clone(),
                provider.clone(),
                network.clone(),
            )
            .await;

            request_pool = updated_request_pool;
            account_instances = fresh_instances;
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    })
    .await
    .expect("task failed");
}
