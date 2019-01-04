use crate::network::Network;
use crate::dns::peers;

pub struct SPV {}

impl SPV {
    pub fn start(&self) {
        let peers = peers(Network::Testnet);
        println!("{:?}", peers)
    }
}