use std::io::Error;
use std::net::SocketAddr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use byteorder::{ByteOrder, LittleEndian};
use bytes::{BufMut, BytesMut};
use hex;
use murmur3::murmur3_32;
use rand::prelude::*;
use sha2::{Digest, Sha256};
use tokio::codec::{Decoder, Encoder};

use crate::netaddr::{NetAddr, NetAddrCodec};
use crate::network::Network;
use crate::transaction::{Transaction, TransactionCodec};
use crate::varint::VarIntCodec;
use crate::varstr::VarStrCodec;

#[derive(Debug)]
pub enum Message {
    Version(VersionMessage),
    VerAck,
    Inv(InvMessage),
    Tx(Transaction),
    Filterload(FilterloadMessage),
    GetBlocks(GetBlocksMessage),
    GetData(GetDataMessage),
    Unknown,
}

impl Message {
    pub fn name(&self) -> &str {
        match self {
            Message::Version(_) => "version",
            Message::VerAck => "verack",
            Message::Inv(_) => "inv",
            Message::Tx(_) => "tx",
            Message::Filterload(_) => "filterload",
            Message::GetBlocks(_) => "getblocks",
            Message::GetData(_) => "getdata",
            Message::Unknown => "unknown",
        }
    }
}

pub struct MessageCodec {
    pub network: Network,
}

impl Encoder for MessageCodec {
    type Item = Message;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut buf: Vec<u8> = Vec::new();

        buf.put_u32_le(self.network.magic_bytes());

        buf.extend(&self.encode_name(&item));

        let payload = match item {
            Message::Version(fields) => {
                let mut payload: Vec<u8> = Vec::new();

                payload.put_i32_le(fields.version);
                payload.put_u64_le(fields.services);
                payload.put_i64_le(fields.timestamp);

                let mut encoded_addr_recv = BytesMut::new();
                NetAddrCodec
                    .encode(fields.addr_recv, &mut encoded_addr_recv)
                    .unwrap();
                payload.extend(encoded_addr_recv);

                let mut encoded_addr_from = BytesMut::new();
                NetAddrCodec
                    .encode(fields.addr_from, &mut encoded_addr_from)
                    .unwrap();
                payload.extend(encoded_addr_from);

                payload.put_u64_le(fields.nonce);

                let mut encoded_ua = BytesMut::new();
                VarStrCodec
                    .encode(fields.user_agent, &mut encoded_ua)
                    .unwrap();
                payload.extend(encoded_ua);

                payload.put_i32_le(fields.start_height);
                payload.put_u8(if fields.relay { 1 } else { 0 });
                payload
            }
            Message::VerAck => Vec::new(),
            Message::Inv(fields) => {
                let mut payload = BytesMut::new();

                VarIntCodec.encode(fields.invs.len(), &mut payload).unwrap();
                for item in fields.invs {
                    InventoryCodec.encode(item, &mut payload).unwrap();
                }

                payload.to_vec()
            }
            Message::Tx(transaction) => {
                let mut payload = BytesMut::with_capacity(1024);
                TransactionCodec.encode(transaction, &mut payload).unwrap();

                payload.to_vec()
            }
            Message::Filterload(fields) => {
                let mut payload = BytesMut::with_capacity(1024);
                VarIntCodec
                    .encode(fields.filter.len(), &mut payload)
                    .unwrap();
                for byte in fields.filter {
                    payload.put_u8(byte);
                }
                payload.put_u32_le(fields.n_hash_funcs);
                payload.put_u32_le(fields.n_tweak);
                payload.put_u8(fields.n_flags);
                payload.to_vec()
            }
            Message::GetBlocks(fields) => {
                let mut payload = BytesMut::with_capacity(1024);
                payload.put_u32_le(fields.version);
                VarIntCodec
                    .encode(fields.block_locator_hashes.len(), &mut payload)
                    .unwrap();
                for hash in fields.block_locator_hashes {
                    dst.extend(&hash);
                }
                payload.extend(&fields.hash_stop);
                payload.to_vec()
            }
            Message::GetData(fields) => {
                let mut payload = BytesMut::new();

                VarIntCodec.encode(fields.invs.len(), &mut payload).unwrap();
                for item in fields.invs {
                    InventoryCodec.encode(item, &mut payload).unwrap();
                }

                payload.to_vec()
            }
            Message::Unknown => panic!(),
        };

        buf.put_u32_le(payload.len() as u32);

        // calc checksum
        let mut hasher = Sha256::new();
        hasher.input(&payload);
        let result_once = hasher.result_reset();
        hasher.input(result_once);
        let checksum = hasher.result();
        buf.extend(&checksum[0..4]);

        buf.extend(payload);

        dst.extend(buf);
        Ok(())
    }
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 24 {
            return Ok(None);
        };
        let _magic = src.split_to(4);
        let name = src.split_to(12);
        let payload_len = LittleEndian::read_u32(&src.split_to(4)) as usize;
        let _payload_checksum = src.split_to(4);
        let payload = src.split_to(payload_len);
        Ok(Some(Message::Unknown))
    }
}

impl MessageCodec {
    pub fn encode_name(&self, item: &Message) -> [u8; 12] {
        let mut bytes = item.name().bytes();
        let mut array = [0; 12];
        for i in 0..12 {
            match bytes.next() {
                Some(b) => array[i] = b,
                None => {
                    // zero-padding
                    array[i] = 0;
                }
            }
        }
        array
    }
}

#[derive(Debug)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetAddr,
    pub addr_from: NetAddr,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

impl VersionMessage {
    pub fn new(address: &SocketAddr) -> Message {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Message::Version(VersionMessage {
            version: 70015,
            services: 0,
            timestamp,
            addr_recv: NetAddr::new(address, &0),
            addr_from: NetAddr::new(address, &0),
            nonce: 0,
            user_agent: hex::encode("bist".to_string()),
            start_height: 0,
            relay: false,
        })
    }
}

#[derive(Debug)]
pub struct InvMessage {
    invs: Vec<Inventory>,
}

#[derive(Debug)]
pub struct Inventory {
    pub inv_type: u32,
    pub hash: String,
}

pub struct InventoryCodec;

impl Encoder for InventoryCodec {
    type Item = Inventory;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u32_le(item.inv_type);
        let mut encoded_hash = BytesMut::new();
        VarStrCodec.encode(item.hash, &mut encoded_hash).unwrap();
        dst.extend(encoded_hash);

        Ok(())
    }
}

#[derive(Debug)]
pub struct FilterloadMessage {
    pub filter: Vec<u8>,
    pub n_hash_funcs: u32,
    pub n_tweak: u32,
    pub n_flags: u8,
}

impl FilterloadMessage {
    pub fn new(data: Vec<u8>) -> Message {
        let n_hash_funcs = 10;
        let mut rng = rand::thread_rng();
        let n_tweak: u32 = rng.gen();

        let mut filter: [u8; 128] = [0; 128];
        for i in 0..n_tweak {
            let idx = murmur3_32(&mut &data[..], n_hash_funcs * 0xFBA4C795 + i);
            filter[(idx >> 3) as usize] |= (1 << (7 & idx)) as u8;
        }

        Message::Filterload(FilterloadMessage {
            filter: filter.to_vec(),
            n_hash_funcs: 10,
            n_tweak: n_tweak,
            n_flags: 1,
        })
    }
}

#[derive(Debug)]
pub struct GetBlocksMessage {
    version: u32,
    block_locator_hashes: Vec<[u8; 32]>,
    hash_stop: [u8; 32],
}

#[derive(Debug)]
pub struct GetDataMessage {
    invs: Vec<Inventory>,
}
