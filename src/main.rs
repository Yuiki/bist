use bist::network::Network;
use bist::spv::SPV;

fn main() {
    let spv = SPV::new(Network::Regtest);
    spv.run();
}
