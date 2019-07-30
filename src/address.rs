use std::io::Write;

use rust_base58::FromBase58;
use secp256k1::PublicKey;

use crate::encode::base58check;
use crate::hash::hash160;

pub fn encode_to_address(pk: &PublicKey) -> String {
    let mut pk_bytes = Vec::new();
    pk_bytes.write_all(&pk.serialize()).unwrap();
    let hashed_pk = hash160(&pk_bytes);
    // 0xEF is the version byte (Testnet)
    let mut v = vec![0x6F];
    v.extend_from_slice(&hashed_pk);
    base58check(&v)
}

pub fn decode_address(address: String) -> Vec<u8> {
    let decoded = address.from_base58().unwrap();
    // drop version byte and checksum
    decoded.get(1..decoded.len() - 4).unwrap().to_vec()
}
