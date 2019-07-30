use std::io::Error;
use std::net::SocketAddr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bytes::BufMut;
use bytes::BytesMut;
use sha2::{Digest, Sha256};
use tokio::codec::{Decoder, Encoder};

use crate::netaddr::{NetAddr, NetAddrCodec};
use crate::network::Network;
use crate::varstr::VarStrCodec;

pub enum Message {
    Version(VersionMessage),
}

impl Message {
    pub fn name(&self) -> &str {
        match self {
            Message::Version(_) => "version",
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
        unimplemented!()
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
            user_agent: "bist".to_string(),
            start_height: 0,
            relay: false,
        })
    }
}
