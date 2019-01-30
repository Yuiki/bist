use bist::spv::SPV;

use bist::network::Network;

fn main() {
    let spv = SPV { network: Network::Testnet };
    spv.run();
}
