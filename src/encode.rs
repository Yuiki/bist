use rust_base58::{FromBase58, ToBase58};
use secp256k1::SecretKey;

use crate::hash::hash256;

pub fn base58check(input: &Vec<u8>) -> String {
    let mut input = input.clone();
    let result = hash256(&input);
    let checksum = result.get(0..4).unwrap();
    input.extend_from_slice(checksum);
    input[..].to_base58()
}

pub fn encode_to_wif(secret_key: &SecretKey) -> String {
    // 0xEF is the version byte (Testnet)
    let mut wif = vec![0xEF];
    wif.extend_from_slice(&secret_key[..].to_vec());
    base58check(&wif)
}

// TODO: add error handling
pub fn decode_wif(wif: &String) -> Vec<u8> {
    let decoded = wif.from_base58().unwrap();
    // drop version byte and checksum
    decoded.get(1..decoded.len() - 4).unwrap().to_vec()
}
