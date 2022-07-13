use starknet::{
    accounts::{Account, Call, SingleOwnerAccount},
    core::{
        chain_id, types::BlockId, types::ConfirmedTransactionReceipt, types::FieldElement,
        types::InvokeFunctionTransactionRequest, utils::get_selector_from_name,
    },
    providers::{Provider, SequencerGatewayProvider},
    signers::{LocalWallet, SigningKey},
};
use std::fs;
use url::Url;
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

use openssl::bn::{BigNum, BigNumContext};
async fn make_rng_request(
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
        .await;

    println!("result is {:?}", result)
}

pub fn starknet_nile_localhost() -> SequencerGatewayProvider {
    SequencerGatewayProvider::new(
        Url::parse("http://127.0.0.1:5050/gateway").unwrap(),
        Url::parse("http://127.0.0.1:5050/feeder_gateway").unwrap(),
    )
}
async fn get_latest_block(provider: SequencerGatewayProvider) -> starknet::core::types::Block {
    let latest_block = provider.get_block(BlockId::Latest).await;
    println!("{:#?}", latest_block);
    return latest_block.unwrap();
}

async fn get_rng_request_events(provider: SequencerGatewayProvider, oracle_address: FieldElement) {
    let block = get_latest_block(provider).await;

    let mut request_indexes: Vec<FieldElement> = Vec::new();
    for tx in block.transaction_receipts {
        let mut fresh_indexes = get_request_events_from_transaction(tx, oracle_address).await;
        if fresh_indexes.len() > 0 {
            request_indexes.append(&mut fresh_indexes)
        }
    }
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

async fn resolve_rng_request(
    account: SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>,
    request_index: FieldElement,
    oracle_address: FieldElement,
    secret_key: Vec<u8>,
    mut vrf: ECVRF,
) {
    let invoke_fn_tx = InvokeFunctionTransactionRequest {
        contract_address: oracle_address,
        entry_point_selector: get_selector_from_name("get_request").unwrap(),
        calldata: vec![request_index],
        signature: [FieldElement::from_hex_be("01").unwrap()].to_vec(),
        max_fee: FieldElement::from_hex_be("01").unwrap(),
    };

    let result = account
        .provider()
        .call_contract(invoke_fn_tx, BlockId::Latest)
        .await;

    let alpha_hash = "f60cfab7e2cb9f2d73b0c2fa4a4bf40c326a7e71fdcdee263b071276522d0eb1";
    let message_vec = hex::decode(alpha_hash).expect("Decoding failed");

    let message: &[u8] = message_vec.as_ref();

    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, &message).unwrap();

    let (gamma_point, c, s) = vrf.decode_proof(&pi).expect("unable to decode proof");

    let mut xbn = BigNum::new().unwrap();
    let mut ybn = BigNum::new().unwrap();

    let mut bn_ctx = BigNumContext::new().unwrap();
    gamma_point
        .affine_coordinates(&vrf.group, &mut xbn, &mut ybn, &mut bn_ctx)
        .unwrap();

    let (x1, x2, x3) = split(xbn, bn_ctx);
    let bn_ctx = BigNumContext::new().unwrap();
    let (y1, y2, y3) = split(ybn, bn_ctx);
    let bn_ctx = BigNumContext::new().unwrap();
    let (c1, c2, c3) = split(c, bn_ctx);
    let bn_ctx = BigNumContext::new().unwrap();
    let (s1, s2, s3) = split(s, bn_ctx);

    let result = account
        .execute(&[Call {
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
            ],
        }])
        .send()
        .await;

    return ();
}

fn split(x: BigNum, mut bn_ctx: BigNumContext) -> (BigNum, BigNum, BigNum) {
    let mut d0 = BigNum::new().unwrap();
    let mut d1 = BigNum::new().unwrap();
    let mut d2 = BigNum::new().unwrap();
    let mut bits_86 = BigNum::from_dec_str("77371252455336267181195264").unwrap();

    let mut rem = BigNum::new().unwrap();

    d0 = x;
    d0.mask_bits(86);

    x.div_rem(&mut rem, &x, &bits_86, &mut bn_ctx).unwrap();

    d1 = x;
    d1.mask_bits(86);

    x.div_rem(&mut rem, &x, &bits_86, &mut bn_ctx).unwrap();

    d2 = x;
    d2.mask_bits(86);

    return (d0, d1, d2);
}

pub async fn resolve_rng_requests(
    provider: SequencerGatewayProvider,
    account: SingleOwnerAccount<SequencerGatewayProvider, LocalWallet>,
    request_indexes: Vec<FieldElement>,
    oracle_address: FieldElement,
    secret_key: Vec<u8>,
) {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();

    for request_index in request_indexes {
        let account_copy = account.clone();
        let sk = secret_key.clone();
        let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
        resolve_rng_request(account_copy, request_index, oracle_address, sk, vrf);
    }
}

fn main() {
    let private_key =
        fs::read_to_string("secrets.txt").expect("Something went wrong reading the file");
    // Query contract event
    let provider = starknet_nile_localhost();
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(
        FieldElement::from_hex_be(&private_key).unwrap(),
    ));
    let account_contract_address = FieldElement::from_hex_be(
        "4077a895eda64b37f4ff7bf9beb16b487c9f9535662fcde096b747fa75643dc",
    )
    .unwrap();
    let oracle_address = FieldElement::from_hex_be(
        "04102e75c500fe57a7ae4825c56500a0395fccab45ad7b5ebdd1ab1545ac7f0b",
    )
    .unwrap();
    let dice_address = FieldElement::from_hex_be(
        "0426a2c5e5f830bb543c120022e5849fbf33fbc26a08f3b8490f895c6328956e",
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
    rt.block_on(resolve_rng_request(
        account_two,
        one,
        oracle_address,
        secret_key,
        vrf,
    ));
    // rt.block_on(get_latest_block(provider));
}
