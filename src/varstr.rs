use std::io::Error;

use bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};

use crate::varint::VarIntCodec;

pub struct VarStrCodec;

impl Encoder for VarStrCodec {
    type Item = String;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let decoded = hex::decode(item).unwrap();
        VarIntCodec.encode(decoded.len(), dst).unwrap();
        dst.extend(decoded);

        Ok(())
    }
}

impl Decoder for VarStrCodec {
    type Item = String;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let len = VarIntCodec.decode(src).unwrap().unwrap();

        let mut bytes: Vec<u8> = Vec::new();
        for _ in 0..len {
            bytes.push(*src.split_to(std::mem::size_of::<u8>()).first().unwrap())
        }

        let encoded = hex::encode(bytes);

        Ok(Some(encoded))
    }
}
