extern crate secp256k1;

use secp256k1::{rand::rngs::OsRng, Message, PublicKey, Secp256k1, SecretKey, SerializedSignature};
use std::fs;
use std::io::Write;

use crate::encode::{decode_wif, encode_to_wif};

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

pub fn sign(msg: &Vec<u8>, secret_key: &SecretKey) -> SerializedSignature {
    let secp = Secp256k1::new();
    let msg = Message::from_slice(msg).unwrap();
    let signature = secp.sign(&msg, secret_key);
    signature.serialize_der()
}

fn save_secret_key(secret_key: &SecretKey) {
    let wif = encode_to_wif(&secret_key);
    let mut file = fs::File::create(KEY_FILENAME).unwrap();
    write!(file, "{}", wif).unwrap();
    file.flush().unwrap();
}

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    secp.generate_keypair(&mut rng)
}
