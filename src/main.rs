use bist::network::Network;
use bist::spv::SPV;

fn main() {
    let spv = SPV {
        network: Network::Regtest,
    };
    spv.run();
}
