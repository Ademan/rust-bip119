//! Tests CTV test vectors from BIP 119
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0119/vectors/ctvhash.json>

#![cfg(feature = "serde")]

use bip119::DefaultCheckTemplateVerifyHash;
use bitcoin::consensus::{Encodable,Decodable};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{hashes::Hash, hex::FromHex, io::Cursor, Transaction};
use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug,Deserialize)]
struct CtvTestVector {
    #[serde(rename = "hex_tx", with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
    transaction: Transaction,

    spend_index: Vec<u32>,

    result: Vec<DefaultCheckTemplateVerifyHash>,

    #[serde(flatten)]
    _remainder: HashMap<String, serde_json::Value>,
}

#[derive(Debug,Deserialize)]
#[serde(untagged)]
enum CtvTestVectorEntry {
    TestVector(CtvTestVector),

    #[allow(dead_code)]
    Documentation(String),
}

fn get_ctv_test_vectors() -> impl Iterator<Item = (Transaction, u32, DefaultCheckTemplateVerifyHash)> {
    let ctv_test_vectors = include_str!("data/ctvhash.json");
    let ctv_test_vectors: Vec<CtvTestVectorEntry> = serde_json::from_str(ctv_test_vectors).expect("failed to parse ctv test vectors");

    ctv_test_vectors.into_iter()
        .filter_map(|entry| {
            match entry {
                CtvTestVectorEntry::Documentation(_) => None,
                CtvTestVectorEntry::TestVector(entry) => Some(entry),
            }
        })
        .flat_map(|entry| {
            entry.spend_index.into_iter()
                .zip(entry.result.into_iter())
                .map(move |(spend_index, result)| (entry.transaction.clone(), spend_index, result))
        })
}

#[test]
fn test_ctv_hash() {
    for (tx, index, expected_ctv_hash) in get_ctv_test_vectors() {
        let ctv_hash = DefaultCheckTemplateVerifyHash::from_transaction(&tx, index);
        assert_eq!(ctv_hash, expected_ctv_hash);
    }
}

fn get_ctv_hash_bytes() -> Vec<u8> {
    // sha256("Activate CTV!")
    Vec::from_hex("b68f63adb2804e999b1d6bfffe060dc004fb40169fa10cb6a6486ddb42200e65").unwrap()
}

fn get_ctv_hash() -> DefaultCheckTemplateVerifyHash {
    DefaultCheckTemplateVerifyHash::from_slice(&get_ctv_hash_bytes()).unwrap()
}

// Probably a bit gratuitous, the rust-bitcoin internal tests for Hash newtypes ought to cover
// this, but there's nothing wrong with belt and suspenders
#[test]
fn test_consensus_decode_encode() {
    let ctv_hash_bytes = get_ctv_hash_bytes();

    let decoded_ctv = DefaultCheckTemplateVerifyHash::consensus_decode(&mut Cursor::new(&ctv_hash_bytes))
        .expect("decode should succeed");

    let ctv_hash = DefaultCheckTemplateVerifyHash::from_slice(ctv_hash_bytes.as_ref()).unwrap();

    assert_eq!(&decoded_ctv, &ctv_hash);

    let mut encoded_bytes = Vec::<u8>::new();
    ctv_hash.consensus_encode(&mut encoded_bytes)
        .expect("Consensus encode shouldn't fail");

    assert_eq!(&ctv_hash_bytes, &encoded_bytes);
}

// Really just asserting that this compiles
#[test]
fn test_secp256k1_sign() {
    let pk = SecretKey::from_str("b68f63adb2804e999b1d6bfffe060dc004fb40169fa10cb6a6486ddb42200e65").unwrap();
    let ctv_hash = get_ctv_hash();
    let secp = Secp256k1::new();

    let keypair = pk.keypair(&secp);

    let _signature = secp.sign_schnorr_no_aux_rand(&ctv_hash.into(), &keypair);
}
