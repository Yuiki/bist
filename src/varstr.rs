use std::io::Error;

use bytes::BytesMut;
use tokio::codec::Encoder;

use crate::varint::VarIntCodec;

pub struct VarStrCodec;

impl Encoder for VarStrCodec {
    type Item = String;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut buf: Vec<u8> = Vec::new();
        VarIntCodec.encode(item.len(), dst).unwrap();
        buf.extend(item.bytes());
        dst.extend(buf);

        Ok(())
    }
}
