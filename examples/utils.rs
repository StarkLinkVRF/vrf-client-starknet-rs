use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

pub fn split_bigint(x: BigNum) -> (BigNum, BigNum, BigNum) {
    let bits_86 = 86;
    let bn_bits_86 = BigNum::from_dec_str("77371252455336267181195264").unwrap();

    let mut d0 = BigNum::new().unwrap();
    d0 = x;

    let mut d1 = BigNum::new().unwrap();
    d1.rshift(&d0, bits_86).unwrap();

    let mut d2 = BigNum::new().unwrap();
    d2.rshift(&d1, bits_86).unwrap();

    d0.mask_bits(86).expect("error masking d0");

    if !d1.le(&bn_bits_86) {
        d1.mask_bits(86).expect("error masking d1");
    }

    if !d2.le(&bn_bits_86) {
        d2.mask_bits(86).expect("error masking d2");
    }

    return (d0, d1, d2);
}

pub fn split_uint256(x: BigNum) -> (BigNum, BigNum) {
    let bits_128 = 128;
    let bn_bits_128 = BigNum::from_dec_str("340282366920938463463374607431768211456").unwrap();

    let mut rem = BigNum::new().unwrap();
    let mut d0 = BigNum::new().unwrap();
    d0 = x;

    let mut d1 = BigNum::new().unwrap();
    d1.rshift(&d0, bits_128).unwrap();

    d0.mask_bits(bits_128).expect("error masking d0");

    if !d1.le(&bn_bits_128) {
        d1.mask_bits(bits_128).expect("error masking d1");
    }

    return (d0, d1);
}

fn main() {}
