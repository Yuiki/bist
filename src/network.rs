#[allow(dead_code)]
#[derive(Clone)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn magic_bytes(&self) -> u32 {
        match self {
            Network::Mainnet => 0xD9B4BEF9,
            Network::Testnet => 0x0709110B,
        }
    }

    pub fn dns_seeds(&self) -> Vec<&str> {
        match self {
            Network::Mainnet => vec![
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.org",
                "seed.bitcoin.sprovoost.nl",
                "seed.bitnodes.io",
                "dnsseed.emzy.de",
            ],
            Network::Testnet => vec![
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.org",
                "seed.testnet.bitcoin.sprovoost.nl",
                "testnet-seed.bluematt.me",
                "bitcoin-testnet.bloqseeds.net",
            ],
        }
    }
}
