use std::io::Error;

use byteorder::{ByteOrder, LittleEndian};
use bytes::{BufMut, BytesMut};
use tokio::codec::{Decoder, Encoder};

pub struct VarIntCodec;

impl Encoder for VarIntCodec {
    type Item = usize;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut buf: Vec<u8> = Vec::new();
        match self.size(item) {
            1 => {
                buf.put_u8(item as u8);
            }
            3 => {
                buf.put_u8(0xFD);
                buf.put_u16_le(item as u16)
            }
            5 => {
                buf.put_u8(0xFE);
                buf.put_u32_le(item as u32)
            }
            _ => {
                buf.put_u8(0xFF);
                buf.put_u64_le(item as u64)
            }
        }
        dst.extend(buf);

        Ok(())
    }
}

impl Decoder for VarIntCodec {
    type Item = usize;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let first = src.split_to(std::mem::size_of::<u8>());
        let first = first.first().unwrap();
        let value = match first {
            0xFD => {
                let bytes = src.split_to(std::mem::size_of::<u16>());
                LittleEndian::read_u16(&bytes) as usize
            }
            0xFE => {
                let bytes = src.split_to(std::mem::size_of::<u32>());
                LittleEndian::read_u32(&bytes) as usize
            }
            0xFF => {
                let bytes = src.split_to(std::mem::size_of::<u64>());
                LittleEndian::read_u64(&bytes) as usize
            }
            _ => *first as usize,
        };
        Ok(Some(value))
    }
}

impl VarIntCodec {
    fn size(&self, item: usize) -> u8 {
        if item < 0xFD {
            1
        } else if item < 0xFFFF {
            3
        } else if item < 0xFFFF_FFFF {
            5
        } else {
            9
        }
    }
}
