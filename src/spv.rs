use std::net::SocketAddr;

use dialoguer::{Input, Select};
use futures::stream::Stream;
use futures::sync::mpsc;
use std::io;
use std::thread;
use tokio::codec::Decoder;
use tokio::net::TcpStream;
use tokio::prelude::future::Future;
use tokio::prelude::Async;
use tokio::prelude::Sink;

use crate::address::encode_to_address;
use crate::dns;
use crate::key;
use crate::message::{Message, MessageCodec, VersionMessage};
use crate::network::Network;
use crate::transaction::Transaction;

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
        stdin: Box<dyn Stream<Item = Message, Error = io::Error> + Send>,
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
                                tokio::spawn(stdin.forward(sink).then(|result| {
                                    if let Err(e) = result {
                                        println!("failed to write to socket: {}", e)
                                    }
                                    Ok(())
                                }));
                                stream.for_each(|msg| Ok(()))
                            })
                    })
            })
            .map_err(|_| {});
        tokio::spawn(client);
    }
}

fn read_stdin(mut tx: mpsc::Sender<Message>) {
    let (sk, pk) = key::read_or_generate_keys();
    let commands = ["1. Show your address", "2. Send"];
    loop {
        let idx = Select::new()
            .with_prompt("Command?")
            .items(&commands)
            .default(0)
            .interact()
            .unwrap();
        match idx {
            0 => {
                let addr = encode_to_address(&pk);
                println!("{}", addr);
            }
            1 => {
                let txid = Input::<String>::new()
                    .with_prompt("TXID?")
                    .interact()
                    .unwrap();
                let idx = Input::<u32>::new().with_prompt("idx?").interact().unwrap();
                let pk_script = Input::<String>::new()
                    .with_prompt("pk_script?")
                    .interact()
                    .unwrap();
                let to = Input::<String>::new()
                    .with_prompt("to?")
                    .interact()
                    .unwrap();
                let value = Input::<i64>::new()
                    .with_prompt("value?")
                    .interact()
                    .unwrap();
                let transaction =
                    Transaction::with_signature(txid, idx, pk_script, to, value, sk, pk);
                tx = match tx.send(Message::Tx(transaction)).wait() {
                    Ok(tx) => tx,
                    Err(_) => break,
                };
            }
            _ => {}
        };
    }
}
