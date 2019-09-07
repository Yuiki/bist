use bist::network::Network;
use bist::spv::SPV;

fn main() {
    let spv = SPV {
        network: Network::Testnet,
    };
    spv.run();
}
