use core::time;
use starknet::{
    accounts::{Account, Call, SingleOwnerAccount},
    core::{
        chain_id, types::BlockId, types::ConfirmedTransactionReceipt, types::FieldElement,
        types::InvokeFunctionTransactionRequest, utils::get_selector_from_name,
    },
    macros::selector,
    providers::{Provider, SequencerGatewayProvider},
    signers::{LocalWallet, SigningKey},
};
use std::{ops::Add, time::Duration, env};
use url::Url;
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

use openssl::{bn::{BigNum, BigNumContext}, ec::EcPoint};
pub async fn make_rng_request(
    account: SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>,
    dice_address: FieldElement,
) {
    let result = account
        .execute(&[Call {
            to: dice_address,
            selector: get_selector_from_name("request_rng").unwrap(),
            calldata: vec![],
        }])
        .send()
        .await
        .expect("error requesting index");

    println!("request_rng  {:?}", result)
}

pub fn starknet_nile_localhost() -> SequencerGatewayProvider {
    SequencerGatewayProvider::new(
        Url::parse("http://127.0.0.1:5050/gateway").unwrap(),
        Url::parse("http://127.0.0.1:5050/feeder_gateway").unwrap(),
    )
}
pub async fn get_latest_block(provider: SequencerGatewayProvider) -> starknet::core::types::Block {
    let latest_block = provider.get_block(BlockId::Latest).await;

    return latest_block.unwrap();
}

async fn get_block(
    provider: SequencerGatewayProvider,
    block_number: u64,
) -> starknet::core::types::Block {
    let latest_block = provider.get_block(BlockId::Number(block_number)).await;

    return latest_block.unwrap();
}

pub async fn get_rng_request_events(
    provider: SequencerGatewayProvider,
    oracle_address: FieldElement,
    block_number: u64,
) -> Vec<FieldElement> {
    let block = get_block(provider, block_number).await;

    let mut request_indexes: Vec<FieldElement> = Vec::new();
    for tx in block.transaction_receipts {
        let mut fresh_indexes = get_request_events_from_transaction(tx, oracle_address).await;
        if fresh_indexes.len() > 0 {
            request_indexes.append(&mut fresh_indexes)
        }
    }

    return request_indexes;
}

async fn get_request_events_from_transaction(
    tx_reciept: ConfirmedTransactionReceipt,
    oracle_address: FieldElement,
) -> Vec<FieldElement> {
    let request_recieved_event = FieldElement::from_hex_be(
        "03ded866cf2d43aad7d6e5e86532c54ec2f559610ec8efd833005abe66bfdd52",
    )
    .unwrap();

    let mut request_indexes: Vec<FieldElement> = Vec::new();
    for event in tx_reciept.events {
        if event.from_address == oracle_address && event.keys[0] == request_recieved_event {
            request_indexes.push(event.data[0])
        }
    }

    return request_indexes;
}

pub async fn get_roll_result(
    dice_address: FieldElement,
    index: FieldElement,
    provider: SequencerGatewayProvider,
) {
    let call_result = provider
        .call_contract(
            InvokeFunctionTransactionRequest {
                contract_address: dice_address,
                entry_point_selector: selector!("get_roll_result"),
                calldata: vec![index],
                signature: vec![],
                max_fee: FieldElement::ZERO,
            },
            BlockId::Latest,
        )
        .await
        .expect("failed to call contract");

    println!("get_roll_result {:?} ", call_result.result);
}

async fn compose_rng_request(
    account: SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>,
    request_index: FieldElement,
    oracle_address: FieldElement,
    secret_key: Vec<u8>,
    mut vrf: ECVRF,
) -> Call {
    let provider = account.provider().clone();

    let call_result = provider
        .call_contract(
            InvokeFunctionTransactionRequest {
                contract_address: oracle_address,
                entry_point_selector: selector!("get_request"),
                calldata: vec![request_index],
                signature: vec![],
                max_fee: FieldElement::ZERO,
            },
            BlockId::Latest,
        )
        .await
        .expect("failed to call contract");

    println!("get_request res {:?} ", call_result.result);

    // VRF proof and hash output
    let pi = vrf
        .prove(&secret_key, call_result.result[1])
        .unwrap();

    let pub_key = vrf.derive_public_key(&secret_key).expect("unable to derive public key");
    let (gamma_point, c, s) = vrf.decode_proof(&pi).expect("unable to decode proof");

    let mut xbn = BigNum::new().unwrap();
    let mut ybn = BigNum::new().unwrap();

    let mut bn_ctx = BigNumContext::new().unwrap();
    gamma_point
        .affine_coordinates(&vrf.group, &mut xbn, &mut ybn, &mut bn_ctx)
        .unwrap();

    let (x1, x2, x3) = split_bigint(xbn, bn_ctx);
    let bn_ctx = BigNumContext::new().unwrap();
    let (y1, y2, y3) = split_bigint(ybn, bn_ctx);
    let bn_ctx = BigNumContext::new().unwrap();
    let (c1, c2, c3) = split_bigint(c, bn_ctx);
    let bn_ctx = BigNumContext::new().unwrap();
    let (s1, s2, s3) = split_bigint(s, bn_ctx);
    let bn_ctx = BigNumContext::new().unwrap();
    
    let mut xbn2 = BigNum::new().unwrap();
    let mut ybn2 = BigNum::new().unwrap();
    let public_key_point = EcPoint::from_bytes(&vrf.group, &pub_key, &mut vrf.bn_ctx).expect("error decoding public key");
    public_key_point
        .affine_coordinates(&vrf.group, &mut xbn2, &mut ybn2, &mut vrf.bn_ctx)
        .unwrap();
    let (px1, px2, px3) = split_bigint(xbn2, bn_ctx);
    let (py1, py2, py3) = split_bigint(ybn2, vrf.bn_ctx);

    println!("request_index {}", request_index);
    println!("x1 {}", x1);
    println!("x2 {}", x2);
    println!("x3 {}", x3);
    println!("y1 {}", y1);
    println!("y2 {}", y2);
    println!("y3 {}", y3);
    println!("c1 {}", c1);
    println!("c2 {}", c2);
    println!("c3 {}", c3);
    println!("s1 {}", s1);
    println!("s2 {}", s2);
    println!("s3 {}", s3);
    println!("px1 {}", px1);
    println!("px2 {}", px2);
    println!("px3 {}", px3);
    println!("py1 {}", py1);
    println!("py2 {}", py2);
    println!("py3 {}", py3);

    return Call {
        to: oracle_address,
        selector: get_selector_from_name("resolve_rng_request").unwrap(),
        calldata: vec![
            request_index,
            FieldElement::from_hex_be(&x1.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&x2.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&x3.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&y1.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&y2.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&y3.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&c1.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&c2.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&c3.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&s1.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&s2.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&s3.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&px1.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&px2.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&px3.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&py1.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&py2.to_hex_str().unwrap().to_string()).unwrap(),
            FieldElement::from_hex_be(&py3.to_hex_str().unwrap().to_string()).unwrap(),
        ],
    };
}

fn split_bigint(x: BigNum, mut bn_ctx: BigNumContext) -> (BigNum, BigNum, BigNum) {
    let mut bits_86 = BigNum::from_dec_str("77371252455336267181195264").unwrap();

    let mut rem = BigNum::new().unwrap();
    let mut d0 = BigNum::new().unwrap();
    d0 = x;

    let mut d1 = BigNum::new().unwrap();
    d1.rshift(&d0, 86).unwrap();

    let mut d2 = BigNum::new().unwrap();
    d2.rshift(&d1, 86).unwrap();

    d0.mask_bits(86).expect("error masking d0");

    if !d1.le(&bits_86) {
        d1.mask_bits(86).expect("error masking d1");
    }

    if !d2.le(&bits_86) {
        d2.mask_bits(86).expect("error masking d2");
    }

    return (d0, d1, d2);
}

fn pack(x1: BigNum, x2: BigNum, x3: BigNum) -> BigNum {
    let mut shifted_x2 = BigNum::new().unwrap();
    shifted_x2.lshift(&x2, 86).unwrap();

    let mut shifted_x3 = BigNum::new().unwrap();
    shifted_x3.lshift(&x3, 172).unwrap();

    let res = x1.add(&shifted_x2).add(&shifted_x3);

    return res;
}
pub async fn resolve_rng_requests(
    account: SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>,
    request_indexes: Vec<FieldElement>,
    oracle_address: FieldElement,
    secret_key: Vec<u8>,
) -> Option<FieldElement> {
    let delay = time::Duration::from_secs(3);

    let mut requests: Vec<Call> = Vec::new();
    for request_index in request_indexes.clone() {
        println!("request_index {}", request_index);
        let sk = secret_key.clone();
        let vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
        let request =
            compose_rng_request(account.clone(), request_index, oracle_address, sk, vrf).await;
        requests.push(request);
    }

    let mut tx_hash: Option<FieldElement> = Option::None;
    let mut is_request_successful = false;

    while is_request_successful == false {
        let call = account.execute(&requests).send().await;
        match call {
            Ok(call) => {
                println!("resolve request method invoked {}", call.transaction_hash);
                tx_hash = Option::Some(call.transaction_hash);
                is_request_successful = true
            }
            Err(error) => {
                println!("Error with resolving rng request \n {}", error);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }

    return tx_hash;
}

fn main() {
    let private_key =
        env::var("WALLET_SECRET").expect("No env variable of key WALLET_SECRET");
    // Query contract event
    let provider = starknet_nile_localhost();
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        FieldElement::from_hex_be(&private_key).unwrap(),
    ));
    let account_contract_address =
        FieldElement::from_hex_be("a2b80a672ba14339997ccf71274f57463a902cd740f9d0f02786bc3b440864")
            .unwrap();
    let oracle_address = FieldElement::from_hex_be(
        "04b8dad9fcdc1b57f65d0464165b387cc520ccdd55440ed1ff1359625ee45a85",
    )
    .unwrap();
    let dice_address = FieldElement::from_hex_be(
        "033593c0bab9d9a7c95a48013ffe56dbe43312dd9ab133c6cc4803a0780894e2",
    )
    .unwrap();

    let account = SingleOwnerAccount::new(
        provider,
        signer,
        account_contract_address,
        chain_id::TESTNET,
    );
    let account_two = account.clone();
    let one = FieldElement::from_hex_be("01").unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    //rt.block_on(make_rng_request(account, dice_address));
    let provider = starknet_nile_localhost();

    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    //rt.block_on(resolve_rng_request(account_two,one,oracle_address,secret_key,vrf,));
    // rt.block_on(get_latest_block(provider));
    //rt.block_on(get_roll_result(dice_address));
}

//TESTS

#[cfg(test)]
mod test_client_lib {
    use openssl::bn::{BigNum, BigNumContext};

    use crate::client_lib;

    #[test]
    fn test_split_bigint() {
        let mut x = BigNum::from_dec_str(
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        )
        .expect("error parsing bignumer");
        let mut bn_ctx = BigNumContext::new().unwrap();
        let (x1, x2, x3) = client_lib::split_bigint(x, bn_ctx);
        println!("x1, x2, x3 {} {} {}", x1, x2, x3);

        let packed = client_lib::pack(x1, x2, x3);

        println!("packed {}", packed);
    }
}
