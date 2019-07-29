extern crate secp256k1;

use secp256k1::{Secp256k1, rand::rngs::OsRng, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use ripemd160::{Ripemd160};
use rust_base58::{ToBase58, FromBase58};
use std::fs::File;
use std::io::{Write};
use std::fs;

static KEY_FILENAME: &'static str = "key";

pub fn read_or_generate_keys() -> (SecretKey, PublicKey) {
    if let Ok(wif) = fs::read_to_string(KEY_FILENAME) {
    let sk = SecretKey::from_slice(&decode_wif(&wif)).unwrap();
    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
    } else {
        let (sk, pk) = generate_keypair();
        save_secret_key(&sk);
        (sk, pk)
    }
}

pub fn address(pk: &PublicKey) -> String {
    let mut pk_bytes = Vec::new();
    pk_bytes.write_all(&pk.serialize()).unwrap();
    let hashed_pk = hash160(&pk_bytes);
    // 0xEF is the version byte (Testnet)
    let mut v = vec![0x6F];
    v.extend_from_slice(&hashed_pk);
    base58check(&v)
}

fn save_secret_key(secret_key: &SecretKey) {
    let wif = encode_to_wif(&secret_key);
    let mut file = File::create(KEY_FILENAME).unwrap();
    write!(file, "{}", wif).unwrap();
    file.flush().unwrap();
}

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    secp.generate_keypair(&mut rng)
}

fn encode_to_wif(secret_key: &SecretKey) -> String {
    // 0xEF is the version byte (Testnet)
    let mut wif = vec![0xEF];
    wif.extend_from_slice(&secret_key[..].to_vec());
    base58check(&wif)
}

fn base58check(input: &Vec<u8>) -> String {
    let mut input = input.clone();
    let result = hash256(&input);
    let checksum = result.get(0..4).unwrap();
    input.extend_from_slice(checksum);
    input[..].to_base58()
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

// apply sha256 and ripemd160
fn hash160(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(input);
    let result = hasher.result();

    let mut hasher = Ripemd160::default();
    hasher.input(&result);
    hasher.result().to_vec()
}
