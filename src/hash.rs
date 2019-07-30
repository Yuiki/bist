use ripemd160::Ripemd160;
use sha2::{Digest, Sha256};

// apply sha256 twice
pub fn hash256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(input);
    let result = hasher.result();

    let mut hasher = Sha256::default();
    hasher.input(&result);
    hasher.result().to_vec()
}

// apply sha256 and ripemd160
pub fn hash160(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.input(input);
    let result = hasher.result();

    let mut hasher = Ripemd160::default();
    hasher.input(&result);
    hasher.result().to_vec()
}
