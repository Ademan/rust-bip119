// SPDX-License-Identifier: CC0-1.0

//! BIP-119 CHECKTEMPLATEVERIFY
//!
//! Implementation of BIP-119 default template hash calculation, as defined at
//! <https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki>

use bitcoin::blockdata::locktime::absolute;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::{hash_newtype, sha256, Hash};
use bitcoin::io::Write;
use bitcoin::{script::PushBytes, Script, Sequence, transaction::Version, Transaction, TxOut};

/// The BIP redefines `OP_NOP4` to fail script evaluation if the top element on
/// the stack is 32 bytes long and does not match the default template hash calculated for the
/// current input index. If the top element is not 32 bytes long, this opcode
/// does nothing. In both cases, the stack is not modified.
pub use bitcoin::opcodes::all::OP_NOP4 as OP_CHECKTEMPLATEVERIFY;

hash_newtype! {
    /// Default CHECKTEMPLATEVERIFY hash of a transaction
    #[hash_newtype(forward)]
    pub struct DefaultCheckTemplateVerifyHash(sha256::Hash);
}

impl AsRef<PushBytes> for DefaultCheckTemplateVerifyHash {
    fn as_ref(&self) -> &PushBytes {
        self.as_byte_array().into()
    }
}

impl From<DefaultCheckTemplateVerifyHash> for bitcoin::secp256k1::Message {
    fn from(hash: DefaultCheckTemplateVerifyHash) -> bitcoin::secp256k1::Message {
        bitcoin::secp256k1::Message::from_digest(hash.to_byte_array())
    }
}

impl Encodable for DefaultCheckTemplateVerifyHash {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for DefaultCheckTemplateVerifyHash {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(reader: &mut R) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(reader)?))
    }
}

/// Build an intermediate hash from an iterator of `Sequence`s
pub fn hash_sequences<I>(sequences: I) -> sha256::Hash
where
    I: IntoIterator<Item = Sequence>,
{
    let mut sequences_sha256 = sha256::Hash::engine();

    for sequence in sequences {
        let sequence: u32 = sequence.to_consensus_u32();
        sequences_sha256.write(&sequence.to_le_bytes()).expect(CTV_ENC_EXPECT_MSG);
    }

    sha256::Hash::from_engine(sequences_sha256)
}

/// Build an intermediate hash from an iterator of script sigs if any script sigs are non-empty
pub fn hash_script_sigs<S, I>(script_sigs: I) -> Option<sha256::Hash>
where
    S: AsRef<Script>,
    I: IntoIterator<Item = S> + Clone,
{
    let any_script_sigs = script_sigs.clone().into_iter()
        .any(|script_sig| !script_sig.as_ref().is_empty());

    if any_script_sigs {
        let mut script_sig_sha256 = sha256::Hash::engine();

        for script_sig in script_sigs {
            script_sig.as_ref().consensus_encode(&mut script_sig_sha256).expect(CTV_ENC_EXPECT_MSG);
        }

        Some(sha256::Hash::from_engine(script_sig_sha256))
    } else {
        None
    }
}

/// Build an intermediate hash from an iterator of `TxOut`s
fn hash_outputs<'a, I: IntoIterator<Item = &'a TxOut>>(outputs: I) -> sha256::Hash {
    let mut outputs_sha256 = sha256::Hash::engine();
    for output in outputs {
        output.consensus_encode(&mut outputs_sha256).expect(CTV_ENC_EXPECT_MSG);
    }

    sha256::Hash::from_engine(outputs_sha256)
}

const CTV_ENC_EXPECT_MSG: &str = "hash writes are infallible";

impl DefaultCheckTemplateVerifyHash {
    /// Calculate the BIP-119 default template for a transaction at a particular input index
    pub fn from_transaction(transaction: &Transaction, input_index: u32) -> Self {
        let script_sig_sha256 = hash_script_sigs(transaction.input.iter().map(|input| &input.script_sig));

        let sequences_sha256 = hash_sequences(transaction.input.iter().map(|input| input.sequence));

        Self::from_components(
            transaction.version,
            transaction.lock_time,
            transaction.input.len() as u32,
            script_sig_sha256,
            sequences_sha256,
            transaction.output.len() as u32,
            hash_outputs(&transaction.output),
            input_index,
        )
    }

    /// Low level function to calculate the BIP-119 default template from intermediate hashes and
    /// individual components.
    pub fn from_components(
        version: Version,
        lock_time: absolute::LockTime,
        vin_count: u32,
        script_sig_sha256: Option<sha256::Hash>,
        sequences_sha256: sha256::Hash,
        vout_count: u32,
        outputs_sha256: sha256::Hash,
        input_index: u32
    ) -> Self {
        // Since sha256::Hash::write() won't fail and consensus_encode() guarantees to never
        // fail unless the underlying Write::write() fails, we don't need to worry about
        // fallibility
        let mut sha256 = sha256::Hash::engine();

        version.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);
        lock_time.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);

        if let Some(script_sig_sha256) = script_sig_sha256 {
            script_sig_sha256.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);
        }

        sha256.write(&vin_count.to_le_bytes()).expect(CTV_ENC_EXPECT_MSG);

        sequences_sha256.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);

        sha256.write(&vout_count.to_le_bytes()).expect(CTV_ENC_EXPECT_MSG);

        outputs_sha256.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);

        sha256.write(&input_index.to_le_bytes()).expect(CTV_ENC_EXPECT_MSG);

        DefaultCheckTemplateVerifyHash(
            sha256::Hash::from_engine(sha256)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bitcoin::{io::Cursor, hex::FromHex};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    use std::str::FromStr;

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

    // Really just asserting that this compiles
    #[test]
    fn test_pushbytes() {
        let ctv_hash = get_ctv_hash();

        let mut script = bitcoin::ScriptBuf::new();
        script.push_slice(ctv_hash);
    }
}
