use bist::address::encode_to_address;
use bist::key;
use bist::network::Network;
use bist::spv::SPV;
use bist::transaction::Transaction;

fn main() {
    let (sk, pk) = key::read_or_generate_keys();
    let addr = encode_to_address(&pk);
    println!("{}", addr);

    let txid = "51760d62a0be09415f2e8facdc0dadc11d8607f4a4dacd7108b98d4027762237".to_string();
    let idx = 0;
    let pk_script = "76a914d5e364b69fecea49149a679938a8ab6ef5962a8888ac".to_string();
    let to = "mkvnrQmwwf5BoJ5v9CPCdm3j6Ns4y8KqLw".to_string();
    let value = 90000;
    let tx = Transaction::with_signature(txid, idx, pk_script, to, value, sk, pk);

    let spv = SPV {
        network: Network::Testnet,
    };
    spv.run();
}
