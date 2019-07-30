use bist::address::encode_to_address;
use bist::key;
use bist::transaction::Transaction;

fn main() {
    let (sk, pk) = key::read_or_generate_keys();
    let addr = encode_to_address(&pk);
    println!("{}", addr);

    let txid = "f4e9490dd11f4102f05eba23ed774a440841b6698a3a9acd8f6faf06cf7f4d13".to_string();
    let idx = 1;
    let pk_script = "76a914d5e364b69fecea49149a679938a8ab6ef5962a8888ac".to_string();
    let to = "mkvnrQmwwf5BoJ5v9CPCdm3j6Ns4y8KqLw".to_string();
    let value = 9000;
    let tx = Transaction::with_signature(txid, idx, pk_script, to, value, sk, pk);

    println!("{}", tx.raw_tx());
}
