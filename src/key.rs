extern crate secp256k1;

use secp256k1::{Secp256k1, rand::rngs::OsRng, SecretKey};
use sha2::{Sha256, Digest};
use rust_base58::{ToBase58, FromBase58};
use std::fs::File;
use std::io::{Write};
use std::fs;

static KEY_FILENAME: &'static str = "key";

pub fn read_or_generate_secret_key() -> Vec<u8> {
    if let Ok(wif) = fs::read_to_string(KEY_FILENAME) {
        decode_wif(&wif)
    } else {
        let sk = generate_secret_key();
        save_secret_key(&sk);
        sk[..].to_vec()
    }
}

fn save_secret_key(secret_key: &SecretKey) {
    let wif = encode_to_wif(&secret_key);
    let mut file = File::create(KEY_FILENAME).unwrap();
    write!(file, "{}", wif).unwrap();
    file.flush().unwrap();
}

fn generate_secret_key() -> SecretKey {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    let (sk, _pk) = secp.generate_keypair(&mut rng);
    sk
}

fn encode_to_wif(secret_key: &SecretKey) -> String {
    // 0xEF is the version byte (Testnet)
    let mut raw_addr = vec![0xEF];
    raw_addr.extend_from_slice(&secret_key[..].to_vec());
    let result = hash256(&raw_addr);
    let checksum = result.get(0..4).unwrap();
    raw_addr.extend_from_slice(checksum);
    raw_addr[..].to_base58()
}

// TODO: add error handling
fn decode_wif(wif: &String) -> Vec<u8> {
    let decoded = wif.from_base58().unwrap();
    // drop version byte and checksum
    decoded.get(1..decoded.len() - 4).unwrap().to_vec()
}

// apply sha256 twice
fn hash256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(input);
    let result = hasher.result();

    let mut hasher = Sha256::default();
    hasher.input(&result);
    hasher.result().to_vec()
}