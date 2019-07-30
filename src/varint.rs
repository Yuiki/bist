use std::io::Error;

use bytes::{BufMut, BytesMut};
use tokio::codec::Encoder;

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
