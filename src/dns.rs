use rand::seq::SliceRandom;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::network::Network;

pub fn peers(network: &Network) -> Vec<SocketAddr> {
        let mut rng = rand::thread_rng();
    let mut v : Vec<SocketAddr> = network
        .dns_seeds()
        .iter()
        .flat_map(|seed| {
            (*seed, 18333)
                .to_socket_addrs()
                .unwrap_or_else(|_| vec![].into_iter())
        })
        .collect();
    v.shuffle(&mut rng);
    v
}
