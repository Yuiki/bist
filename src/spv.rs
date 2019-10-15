use std::net::SocketAddr;

use dialoguer::{Input, Select};
use futures::stream::Stream;
use futures::sync::mpsc;
use std::io;
use std::io::Write;
use std::thread;
use tokio::codec::Decoder;
use tokio::net::TcpStream;
use tokio::prelude::future::Future;
use tokio::prelude::Async;
use tokio::prelude::Sink;

use crate::address::encode_to_address;
use crate::dns;
use crate::hash::hash160;
use crate::key;
use crate::message::{
    FilterloadMessage, GetBlocksMessage, GetDataMessage, Inventory, Message, MessageCodec,
    VersionMessage,
};
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
        // let peer = peers.first().unwrap();
        let peer = &"127.0.0.1:18444".parse::<SocketAddr>().unwrap();
        let (stdin_tx, stdin_rx) = mpsc::unbounded();
        let tmp = stdin_tx.clone();
        thread::spawn(|| read_stdin(tmp));
        let stdin_rx = stdin_rx.map_err(|_| panic!());

        self.connect(&peer, Box::new(stdin_rx), stdin_tx);

        Ok(Async::Ready(()))
    }

    fn connect(
        &self,
        addr: &SocketAddr,
        stdin: Box<dyn Stream<Item = Message, Error = io::Error> + Send>,
        stdin_tx: futures::sync::mpsc::UnboundedSender<Message>,
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
                    .and_then(move |(_msg, framed)| {
                        framed
                            .send(Message::VerAck)
                            .map(|framed| framed.into_future())
                            .and_then(|framed| framed.map_err(|(e, _)| e))
                            .and_then(move |(_msg, framed)| {
                                let (sink, stream) = framed.split();
                                tokio::spawn(stdin.forward(sink).then(|result| {
                                    if let Err(e) = result {
                                        println!("failed to write to socket: {}", e)
                                    }
                                    Ok(())
                                }));
                                stream.for_each(move |msg| {
                                    println!("{:?}", msg);
                                    match msg {
                                        Message::Inv(fields) => {
                                            let filtered_invs: Vec<Inventory> = fields
                                                .invs
                                                .iter()
                                                .filter(|inv| inv.inv_type == 2)
                                                .map(|inv| Inventory {
                                                    inv_type: 3,
                                                    hash: inv.hash,
                                                })
                                                .collect();
                                            let get_data = Message::GetData(GetDataMessage {
                                                invs: filtered_invs,
                                            });
                                            stdin_tx.clone().wait().send(get_data);
                                        }
                                        _ => {}
                                    }
                                    Ok(())
                                })
                            })
                    })
            })
            .map_err(|e| {
                println!("{}", e);
            });
        tokio::spawn(client);
    }
}

fn read_stdin(mut tx: mpsc::UnboundedSender<Message>) {
    let (sk, pk) = key::read_or_generate_keys();
    let commands = ["1. Show your address", "2. Send", "3. Show your balance"];
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
            2 => {
                let mut pk_bytes = Vec::new();
                pk_bytes.write_all(&pk.serialize()).unwrap();
                let hashed_pk = hash160(&pk_bytes);
                let filterload = FilterloadMessage::new(hashed_pk);
                tx = match tx.send(filterload).wait() {
                    Ok(tx) => tx,
                    Err(_) => break,
                };

                let mut blockid_bytes = hex::decode(
                    &"3967a9ab3a05c17fa3f103c04f3fedfac6f85d42895aab4368fcb59e639c564a",
                )
                .unwrap();
                blockid_bytes.reverse();
                let mut array = [0; 32];
                let bytes = &blockid_bytes[..array.len()];
                array.copy_from_slice(bytes);
                let zero_hash: [u8; 32] = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ];
                let getblocks = GetBlocksMessage {
                    version: 70015,
                    block_locator_hashes: vec![array],
                    hash_stop: zero_hash,
                };
                tx = match tx.send(Message::GetBlocks(getblocks)).wait() {
                    Ok(tx) => tx,
                    Err(_) => break,
                };
            }
            _ => {}
        };
    }
}
