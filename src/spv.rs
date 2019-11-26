use bytes::BytesMut;
use dialoguer::{Input, Select};
use futures::stream::Stream;
use futures::sync::mpsc;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::{thread, time};
use tokio::codec::{Decoder, Encoder};
use tokio::net::TcpStream;
use tokio::prelude::{future::Future, Async, Sink};

use crate::address::{decode_address, encode_to_address};
use crate::hash::{hash160, hash256};
use crate::key;
use crate::message::{
    FilterloadMessage, GetBlocksMessage, GetDataMessage, Inventory, Message, MessageCodec,
    VersionMessage,
};
use crate::network::Network;
use crate::transaction::{Transaction, TransactionCodec, TxOut};

pub struct SPV {
    network: Network,
    txs: Arc<Mutex<Vec<Transaction>>>,
    requested_counts: Arc<Mutex<usize>>,
    received_counts: Arc<Mutex<usize>>,
    synced: Arc<Mutex<bool>>,
}

impl SPV {
    pub fn new(network: Network) -> SPV {
        SPV {
            network: network,
            txs: Arc::new(Mutex::new(Vec::new())),
            requested_counts: Arc::new(Mutex::new(0)),
            received_counts: Arc::new(Mutex::new(0)),
            synced: Arc::new(Mutex::new(false)),
        }
    }
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
        // let peers = dns::peers(&self.network);
        // let peer = peers.first().unwrap();
        let peer = &"127.0.0.1:18444".parse::<SocketAddr>().unwrap();

        let (stdin_tx, stdin_rx) = mpsc::unbounded();
        let stdin_tx2 = stdin_tx.clone();
        let synced = self.synced.clone();
        let txs = self.txs.clone();
        thread::spawn(|| read_stdin(stdin_tx, synced, txs));

        let stdin_rx = stdin_rx.map_err(|_| panic!());
        self.sync(&peer, Box::new(stdin_rx), stdin_tx2);

        Ok(Async::Ready(()))
    }

    fn sync(
        &self,
        addr: &SocketAddr,
        stdin: Box<dyn Stream<Item = Message, Error = io::Error> + Send>,
        stdin_tx: futures::sync::mpsc::UnboundedSender<Message>,
    ) {
        let addr = addr.clone();
        let network = self.network.clone();
        let txs = self.txs.clone();
        let requested_counts = self.requested_counts.clone();
        let received_counts = self.received_counts.clone();
        let synced = self.synced.clone();

        let client = TcpStream::connect(&addr)
            .and_then(move |stream| {
                let framed = MessageCodec { network }.framed(stream);
                let (sink, stream) = framed.split();

                tokio::spawn(stdin.forward(sink).then(|_| Ok(())));

                let version = VersionMessage::new(&addr);
                stdin_tx.clone().wait().send(version).unwrap();

                stream.for_each(move |msg| {
                    match msg {
                        Message::Version(_) => {
                            stdin_tx.clone().wait().send(Message::VerAck).unwrap();
                        }
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
                            stdin_tx.clone().wait().send(get_data).unwrap();

                            let mut requested_counts = requested_counts.lock().unwrap();
                            *requested_counts += fields.invs.len();
                        }
                        Message::MerkleBlock(_) => {
                            let mut received_counts = received_counts.lock().unwrap();
                            *received_counts += 1;

                            let requested_counts = requested_counts.lock().unwrap();
                            if *received_counts == *requested_counts {
                                let mut synced = synced.lock().unwrap();
                                *synced = true;
                            }
                        }
                        Message::Tx(fields) => {
                            let mut txs = txs.lock().unwrap();
                            txs.push(fields);
                        }
                        _ => {}
                    };
                    Ok(())
                })
            })
            .map_err(|_| {});
        tokio::spawn(client);
    }
}

fn read_stdin(
    mut tx: mpsc::UnboundedSender<Message>,
    synced: Arc<Mutex<bool>>,
    txs: Arc<Mutex<Vec<Transaction>>>,
) {
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
                if !*synced.lock().unwrap() {
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
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
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

                while !*synced.lock().unwrap() {
                    thread::sleep(time::Duration::from_millis(100));
                }

                let addr = encode_to_address(&pk);
                let pk_hash = decode_address(addr);
                let txs = txs.lock().unwrap().clone();
                let balance = txs
                    .iter()
                    .flat_map(|tx| {
                        let filtered: Vec<&TxOut> = tx
                            .tx_outs
                            .iter()
                            .filter(|out| {
                                let mut expected = vec![118, 169, 20];
                                expected.extend(&pk_hash);
                                expected.extend(vec![136, 172]);
                                let actual = hex::decode(&out.pk_script).unwrap();
                                expected == actual
                            })
                            .enumerate()
                            .filter(|(idx, _)| {
                                let mut raw_tx = BytesMut::with_capacity(1000);
                                TransactionCodec.encode(tx.clone(), &mut raw_tx).unwrap();
                                let txid = hash256(&raw_tx);

                                !txs.iter().any(|tx| {
                                    tx.tx_ins.iter().any(|tx_in| {
                                        tx_in.previous_output.hash.to_vec() == txid
                                            && tx_in.previous_output.index == (*idx as u32)
                                    })
                                })
                            })
                            .map(|(_, out)| out)
                            .collect();
                        filtered
                    })
                    .fold(0, |acc, x| acc + x.value);

                println!("You have {:?} BTC", balance / 100000000);
            }
            _ => {}
        };
    }
}
