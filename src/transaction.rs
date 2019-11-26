use std::io::Error;

use byteorder::{ByteOrder, LittleEndian};
use bytes::{BufMut, BytesMut};
use hex;
use secp256k1::{PublicKey, SecretKey};
use tokio::codec::{Decoder, Encoder};

use crate::address::decode_address;
use crate::hash;
use crate::key;
use crate::script::Opcode;
use crate::varint::VarIntCodec;
use crate::varstr::VarStrCodec;

#[derive(Debug, Clone)]
pub struct Transaction {
    pub version: i32,
    pub tx_ins: Vec<TxIn>,
    pub tx_outs: Vec<TxOut>,
    pub lock_time: i32,
}

impl Transaction {
    pub fn with_signature(
        txid: String,
        idx: u32,
        script_pub_key: String,
        to: String,
        value: i64,
        sk: SecretKey,
        pk: PublicKey,
    ) -> Transaction {
        let unsigned_tx = Transaction::of(txid.clone(), idx, script_pub_key, to.clone(), value);

        let mut payload = BytesMut::with_capacity(200);
        TransactionCodec.encode(unsigned_tx, &mut payload).unwrap();
        // hash type code
        payload.put_i32_le(1);

        let txhash = hash::hash256(&payload.to_vec());
        let signature = key::sign(&txhash, &sk);
        let mut buf: Vec<u8> = Vec::new();
        buf.put_u8((signature.len() as u8) + 1 /* for hash code */);
        buf.extend(&signature[..]);
        // hash code
        buf.put_u8(1);
        let serialized_pk = pk.serialize();
        buf.put_u8(serialized_pk.len() as u8);
        buf.extend(&serialized_pk[..]);

        Transaction::of(txid, idx, hex::encode(buf), to, value)
    }

    pub fn of(
        txid: String,
        idx: u32,
        script_pub_key: String,
        to: String,
        value: i64,
    ) -> Transaction {
        let mut txid_bytes = hex::decode(&txid).unwrap();
        txid_bytes.reverse();
        let mut hash = [0; 32];
        let bytes = &txid_bytes[..hash.len()];
        hash.copy_from_slice(bytes);
        let out_point = OutPoint {
            hash: hash,
            index: idx,
        };
        let tx_in = TxIn {
            previous_output: out_point,
            signature_script: script_pub_key,
            sequence: 0xFFFFFFFF,
        };

        let pk_hash = decode_address(to);
        let mut pk_script = vec![
            Opcode::Dup.value(),
            Opcode::Hash160.value(),
            pk_hash.len() as u8,
        ];
        pk_script.extend(&pk_hash);
        pk_script.extend(&[Opcode::EqualVerify.value(), Opcode::Checksig.value()]);

        let tx_out = TxOut {
            value: value,
            pk_script: hex::encode(pk_script),
        };

        Transaction {
            version: 1,
            tx_ins: vec![tx_in],
            tx_outs: vec![tx_out],
            lock_time: 0,
        }
    }

    pub fn raw_tx(self) -> String {
        let mut rawtx = BytesMut::with_capacity(1024);
        TransactionCodec.encode(self, &mut rawtx).unwrap();
        hex::encode(rawtx)
    }
}

pub struct TransactionCodec;

impl Encoder for TransactionCodec {
    type Item = Transaction;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_i32_le(item.version);
        VarIntCodec.encode(item.tx_ins.len(), dst).unwrap();
        item.tx_ins.into_iter().for_each(|tx_in| {
            TxInCodec.encode(tx_in, dst).unwrap();
        });
        VarIntCodec.encode(item.tx_outs.len(), dst).unwrap();
        item.tx_outs.into_iter().for_each(|tx_out| {
            TxOutCodec.encode(tx_out, dst).unwrap();
        });
        dst.put_i32_le(item.lock_time);
        Ok(())
    }
}

impl Decoder for TransactionCodec {
    type Item = Transaction;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let version = LittleEndian::read_i32(&src.split_to(std::mem::size_of::<i32>()));
        let tx_in_count = VarIntCodec.decode(src).unwrap().unwrap();
        let tx_ins = (0..tx_in_count)
            .map(|_| TxInCodec.decode(src).unwrap().unwrap())
            .collect();

        let tx_out_count = VarIntCodec.decode(src).unwrap().unwrap();
        let tx_outs = (0..tx_out_count)
            .map(|_| TxOutCodec.decode(src).unwrap().unwrap())
            .collect();

        let lock_time = LittleEndian::read_i32(&src.split_to(std::mem::size_of::<i32>()));

        let tx = Transaction {
            version: version,
            tx_ins: tx_ins,
            tx_outs: tx_outs,
            lock_time: lock_time,
        };
        Ok(Some(tx))
    }
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub signature_script: String,
    pub sequence: u32,
}

struct TxInCodec;

impl Encoder for TxInCodec {
    type Item = TxIn;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        OutPointCodec.encode(item.previous_output, dst).unwrap();
        VarStrCodec.encode(item.signature_script, dst).unwrap();
        dst.put_u32_le(item.sequence);
        Ok(())
    }
}

impl Decoder for TxInCodec {
    type Item = TxIn;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let previous_output = OutPointCodec.decode(src).unwrap().unwrap();
        let signature_script = VarStrCodec.decode(src).unwrap().unwrap();
        let sequence = LittleEndian::read_u32(&src.split_to(std::mem::size_of::<u32>()));

        let tx_in = TxIn {
            previous_output: previous_output,
            signature_script: signature_script,
            sequence: sequence,
        };
        Ok(Some(tx_in))
    }
}

#[derive(Debug, Clone)]
pub struct OutPoint {
    pub hash: [u8; 32],
    pub index: u32,
}

struct OutPointCodec;

impl Encoder for OutPointCodec {
    type Item = OutPoint;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item.hash);
        dst.put_u32_le(item.index);
        Ok(())
    }
}

impl Decoder for OutPointCodec {
    type Item = OutPoint;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut hash = [0; 32];
        hash.copy_from_slice(&src.split_to(32)[..]);
        let index = LittleEndian::read_u32(&src.split_to(std::mem::size_of::<u32>()));
        let out_point = OutPoint {
            hash: hash,
            index: index,
        };
        Ok(Some(out_point))
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: i64,
    pub pk_script: String,
}

struct TxOutCodec;

impl Encoder for TxOutCodec {
    type Item = TxOut;
    type Error = Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_i64_le(item.value);
        VarStrCodec.encode(item.pk_script, dst).unwrap();
        Ok(())
    }
}

impl Decoder for TxOutCodec {
    type Item = TxOut;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let value = LittleEndian::read_i64(&src.split_to(std::mem::size_of::<i64>()));
        let pk_script = VarStrCodec.decode(src).unwrap().unwrap();
        let tx_out = TxOut {
            value: value,
            pk_script: pk_script,
        };
        Ok(Some(tx_out))
    }
}
