use std::net::SocketAddr;

use tokio::codec::Decoder;
use tokio::net::TcpStream;
use tokio::prelude::Async;
use tokio::prelude::future::Future;
use tokio::prelude::Sink;

use crate::dns;
use crate::message::{MessageCodec, VersionMessage};
use crate::network::Network;

pub struct SPV {
    pub network: Network
}

impl Future for SPV {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        self.start()
    }
}

impl SPV {
    pub fn run(self) {
        tokio::run(self);
    }

    fn start(&self) -> Result<Async<()>, ()> {
        let peers = dns::peers(&self.network);

        let peer = peers.first().unwrap();
        // for testing
        let peer = &"127.0.0.1:6142".parse::<SocketAddr>().unwrap();
        self.connect(peer);

        Ok(Async::Ready(()))
    }

    fn connect(&self, addr: &SocketAddr) {
        let addr = addr.clone();
        let network = self.network.clone();

        let client = TcpStream::connect(&addr).and_then(move |stream| {
            // handshake
            let version = VersionMessage::new(&addr);
            let framed = MessageCodec { network }.framed(stream);
            framed.send(version).then(|r| {
                Ok(())
            })
        }).map_err(|e| {});
        tokio::spawn(client);
    }
}