use std::net::SocketAddr;

use futures::stream::Stream;
use futures::sync::mpsc;
use std::io::{self, Read};
use std::thread;
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

        let (stdin_tx, stdin_rx) = mpsc::channel(0);
        thread::spawn(|| read_stdin(stdin_tx));
        let stdin_rx = stdin_rx.map_err(|_| panic!());

        self.connect(&peer, Box::new(stdin_rx));

        Ok(Async::Ready(()))
    }

    fn connect(
        &self,
        addr: &SocketAddr,
        stdin: Box<dyn Stream<Item = Vec<u8>, Error = io::Error> + Send>,
    ) {
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
                                let (sink, stream) = framed.split();
                                tokio::spawn(stdin.map(|data| Message::VerAck).forward(sink).then(
                                    |result| {
                                        if let Err(e) = result {
                                            println!("failed to write to socket: {}", e)
                                        }
                                        Ok(())
                                    },
                                ));
                                stream.for_each(|msg| Ok(()))
                            })
                    })
            })
            .map_err(|_| {});
        tokio::spawn(client);
    }
}

fn read_stdin(mut tx: mpsc::Sender<Vec<u8>>) {
    let mut stdin = io::stdin();
    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf) {
            Err(_) | Ok(0) => break,
            Ok(n) => n,
        };
        buf.truncate(n);
        tx = match tx.send(buf).wait() {
            Ok(tx) => tx,
            Err(_) => break,
        };
    }
}
