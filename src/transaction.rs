use std::io::Error;
use std::iter::FromIterator;

use arrayvec::ArrayVec;
use bytes::{BufMut, BytesMut};
use hex;
use secp256k1::{PublicKey, SecretKey};
use tokio::codec::Encoder;

use crate::address::decode_address;
use crate::hash;
use crate::key;
use crate::script::Opcode;
use crate::varint::VarIntCodec;
use crate::varstr::VarStrCodec;

pub struct Transaction {
    version: i32,
    tx_in: TxIn,
    tx_out: TxOut,
    lock_time: i32,
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
        let out_point = OutPoint {
            hash: ArrayVec::from_iter(txid_bytes.into_iter()),
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
            version: 0,
            tx_in: tx_in,
            tx_out: tx_out,
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
        VarIntCodec.encode(1, dst).unwrap();
        TxInCodec.encode(item.tx_in, dst).unwrap();
        VarIntCodec.encode(1, dst).unwrap();
        TxOutCodec.encode(item.tx_out, dst).unwrap();
        dst.put_i32_le(item.lock_time);
        Ok(())
    }
}

struct TxIn {
    previous_output: OutPoint,
    signature_script: String,
    sequence: u32,
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

struct OutPoint {
    hash: ArrayVec<[u8; 32]>,
    index: u32,
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

struct TxOut {
    value: i64,
    pk_script: String,
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
