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
    MerkleBlock(MerkleBlockMessage),
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
            Message::MerkleBlock(_) => "merkleblock",
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
                let mut payload = BytesMut::new();
                VersionCodec.encode(fields, &mut payload).unwrap();
                payload.to_vec()
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
                    payload.extend(&hash);
                }
                payload.extend(&fields.hash_stop);
                payload.to_vec()
            }
            Message::GetData(fields) => {
                let mut payload = BytesMut::with_capacity(1024);

                VarIntCodec.encode(fields.invs.len(), &mut payload).unwrap();
                for item in fields.invs {
                    InventoryCodec.encode(item, &mut payload).unwrap();
                }

                payload.to_vec()
            }
            Message::MerkleBlock(_) | Message::Unknown => panic!(),
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
        let payload_len = LittleEndian::read_u32(&src[16..20]);
        if (src.len() as u32) < payload_len {
            return Ok(None);
        };
        let _magic = src.split_to(4);
        let name = String::from_utf8(src.split_to(12).to_vec()).unwrap();
        let name = name.trim_matches(char::from(0));
        let payload_len = LittleEndian::read_u32(&src.split_to(4)) as usize;
        let _payload_checksum = src.split_to(4);
        if src.len() < payload_len {
            return Ok(None);
        }
        let mut payload = src.split_to(payload_len);
        let msg = match name {
            "version" => {
                let fields = VersionCodec.decode(&mut payload).unwrap().unwrap();
                Message::Version(fields)
            }
            "verack" => Message::VerAck,
            "inv" => {
                let len = VarIntCodec.decode(&mut payload).unwrap().unwrap();
                let invs = (0..len)
                    .map(|_| InventoryCodec.decode(&mut payload).unwrap().unwrap())
                    .collect();
                Message::Inv(InvMessage { invs: invs })
            }
            "merkleblock" => {
                let version = LittleEndian::read_i32(&payload.split_to(std::mem::size_of::<i32>()));
                let mut prev_block = [0; 32];
                prev_block.copy_from_slice(&payload.split_to(32)[..]);
                let mut merkle_root = [0; 32];
                merkle_root.copy_from_slice(&payload.split_to(32)[..]);
                let timestamp =
                    LittleEndian::read_u32(&payload.split_to(std::mem::size_of::<u32>()));
                let bits = LittleEndian::read_u32(&payload.split_to(std::mem::size_of::<u32>()));
                let nonce = LittleEndian::read_u32(&payload.split_to(std::mem::size_of::<u32>()));
                let total_transactions =
                    LittleEndian::read_u32(&payload.split_to(std::mem::size_of::<u32>()));
                let hashes_len = VarIntCodec.decode(&mut payload).unwrap().unwrap();
                let hashes: Vec<[u8; 32]> = (0..hashes_len)
                    .map(|_| {
                        let mut hash = [0; 32];
                        hash.copy_from_slice(&payload.split_to(32)[..]);
                        hash
                    })
                    .collect();
                let flag_bytes = VarIntCodec.decode(&mut payload).unwrap().unwrap();
                let flags: Vec<u8> = (0..flag_bytes)
                    .map(|_| {
                        let first = payload.split_to(std::mem::size_of::<u8>());
                        *first.first().unwrap()
                    })
                    .collect();
                Message::MerkleBlock(MerkleBlockMessage {
                    version: version,
                    prev_block: prev_block,
                    merkle_root: merkle_root,
                    timestamp: timestamp,
                    bits: bits,
                    nonce: nonce,
                    total_transactions: total_transactions,
                    hashes: hashes,
                    flags: flags,
                })
            }
            "tx" => {
                let transaction = TransactionCodec.decode(&mut payload).unwrap().unwrap();
                Message::Tx(transaction)
            }
            _ => Message::Unknown,
        };
        Ok(Some(msg))
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
            services: 4,
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

pub struct VersionCodec;

impl Encoder for VersionCodec {
    type Item = VersionMessage;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_i32_le(item.version);
        dst.put_u64_le(item.services);
        dst.put_i64_le(item.timestamp);

        let mut encoded_addr_recv = BytesMut::new();
        NetAddrCodec
            .encode(item.addr_recv, &mut encoded_addr_recv)
            .unwrap();
        dst.extend(encoded_addr_recv);

        let mut encoded_addr_from = BytesMut::new();
        NetAddrCodec
            .encode(item.addr_from, &mut encoded_addr_from)
            .unwrap();
        dst.extend(encoded_addr_from);

        dst.put_u64_le(item.nonce);

        let mut encoded_ua = BytesMut::new();
        VarStrCodec
            .encode(item.user_agent, &mut encoded_ua)
            .unwrap();
        dst.extend(encoded_ua);

        dst.put_i32_le(item.start_height);
        dst.put_u8(if item.relay { 1 } else { 0 });

        Ok(())
    }
}

impl Decoder for VersionCodec {
    type Item = VersionMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let version = LittleEndian::read_i32(&src.split_to(std::mem::size_of::<i32>()));
        let services = LittleEndian::read_u64(&src.split_to(std::mem::size_of::<u64>()));
        let timestamp = LittleEndian::read_i64(&src.split_to(std::mem::size_of::<i64>()));
        let addr_recv = NetAddrCodec.decode(src).unwrap().unwrap();
        let addr_from = NetAddrCodec.decode(src).unwrap().unwrap();
        let nonce = LittleEndian::read_u64(&src.split_to(std::mem::size_of::<u64>()));
        let user_agent = VarStrCodec.decode(src).unwrap().unwrap();
        let start_height = LittleEndian::read_i32(&src.split_to(std::mem::size_of::<i32>()));
        let relay = *src.first().unwrap() == 1;

        let version = VersionMessage {
            version: version,
            services: services,
            timestamp: timestamp,
            addr_recv: addr_recv,
            addr_from: addr_from,
            nonce: nonce,
            user_agent: user_agent,
            start_height: start_height,
            relay: relay,
        };
        Ok(Some(version))
    }
}

#[derive(Debug)]
pub struct InvMessage {
    pub invs: Vec<Inventory>,
}

#[derive(Debug)]
pub struct Inventory {
    pub inv_type: u32,
    pub hash: [u8; 32],
}

pub struct InventoryCodec;

impl Encoder for InventoryCodec {
    type Item = Inventory;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u32_le(item.inv_type);
        dst.extend(&item.hash);

        Ok(())
    }
}

impl Decoder for InventoryCodec {
    type Item = Inventory;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let inv_type = LittleEndian::read_u32(&src.split_to(std::mem::size_of::<u32>()));
        let mut hash = [0; 32];
        hash.copy_from_slice(&src.split_to(32)[..]);
        let inv = Inventory {
            inv_type: inv_type,
            hash: hash,
        };
        Ok(Some(inv))
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
        let n_hash_funcs: u32 = 10;
        let mut rng = rand::thread_rng();
        let n_tweak: u32 = rng.gen();

        let mut filter: [u8; 128] = [0; 128];
        for i in 0..n_hash_funcs {
            let idx = murmur3_32(
                &mut &data[..],
                (0xFBA4C795 as u32).wrapping_mul(i).wrapping_add(n_tweak),
            ) % ((filter.len() as u32) * 8);
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
    pub version: u32,
    pub block_locator_hashes: Vec<[u8; 32]>,
    pub hash_stop: [u8; 32],
}

#[derive(Debug)]
pub struct GetDataMessage {
    pub invs: Vec<Inventory>,
}

#[derive(Debug)]
pub struct MerkleBlockMessage {
    pub version: i32,
    pub prev_block: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
    pub total_transactions: u32,
    pub hashes: Vec<[u8; 32]>,
    pub flags: Vec<u8>,
}
