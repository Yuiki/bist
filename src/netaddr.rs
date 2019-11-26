use std::clone::Clone;
use std::io::Error;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use bytes::{BufMut, BytesMut};
use tokio::codec::{Decoder, Encoder};

#[derive(Debug)]
pub struct NetAddr {
    pub services: u64,
    pub address: [u16; 8],
    pub port: u16,
}

impl NetAddr {
    pub fn new(addr: &SocketAddr, services: &u64) -> NetAddr {
        let services = services.clone();
        let (addr, port) = match addr {
            SocketAddr::V4(addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().segments(), addr.port()),
        };
        NetAddr {
            address: addr,
            port,
            services,
        }
    }
}

pub struct NetAddrCodec;

impl Encoder for NetAddrCodec {
    type Item = NetAddr;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.put_u64_le(item.services);
        item.address.iter().for_each(|b| {
            buf.put_u16_le(*b);
        });
        buf.put_u16_le(item.port);
        dst.extend(buf);

        Ok(())
    }
}

impl Decoder for NetAddrCodec {
    type Item = NetAddr;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let services = LittleEndian::read_u64(&src.split_to(std::mem::size_of::<u64>()));
        let mut address = [0; 8];
        for i in 0..8 {
            address[i] = LittleEndian::read_u16(&src.split_to(std::mem::size_of::<u16>()));
        }
        let port = LittleEndian::read_u16(&src.split_to(std::mem::size_of::<u16>()));

        let net_addr = NetAddr {
            services: services,
            address: address,
            port: port,
        };
        Ok(Some(net_addr))
    }
}
