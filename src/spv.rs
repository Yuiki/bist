use std::net::SocketAddr;

use futures::stream::Stream;
use tokio::codec::Decoder;
use tokio::net::TcpStream;
use tokio::prelude::future::Future;
use tokio::prelude::Async;
use tokio::prelude::Sink;

use crate::dns;
use crate::message::{Message, MessageCodec, VersionMessage};
use crate::network::Network;

pub struct SPV {
    pub network: Network,
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
        self.connect(peer);

        Ok(Async::Ready(()))
    }

    fn connect(&self, addr: &SocketAddr) {
        let addr = addr.clone();
        let network = self.network.clone();

        let client = TcpStream::connect(&addr)
            .and_then(move |stream| {
                // handshake
                let version = VersionMessage::new(&addr);
                let framed = MessageCodec { network }.framed(stream);
                framed
                    .send(version)
                    .map(|framed| framed.into_future())
                    .and_then(|future| future.map_err(|(e, _)| e))
                    .and_then(|(_msg, framed)| {
                        framed
                            .send(Message::VerAck)
                            .map(|framed| framed.into_future())
                            .and_then(|framed| framed.map_err(|(e, _)| e))
                            .and_then(|(_msg, framed)| {
                                framed.for_each(|msg| {
                                    println!("{:?}", msg);
                                    Ok(())
                                })
                            })
                    })
            })
            .map_err(|_| {});
        tokio::spawn(client);
    }
}
