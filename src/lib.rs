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

/// Build an intermediate hash from an iterator of [`Sequence`]s
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

/// Build an intermediate hash from an iterator of [`TxOut`]s
pub fn hash_outputs<'a, I: IntoIterator<Item = &'a TxOut>>(outputs: I) -> sha256::Hash {
    let mut outputs_sha256 = sha256::Hash::engine();
    for output in outputs {
        output.consensus_encode(&mut outputs_sha256).expect(CTV_ENC_EXPECT_MSG);
    }

    sha256::Hash::from_engine(outputs_sha256)
}

const CTV_ENC_EXPECT_MSG: &str = "hash writes are infallible";

impl DefaultCheckTemplateVerifyHash {
    /// Calculate the BIP-119 default template for a transaction at a particular input index
    /// # Examples
    ///
    /// ## A simple, naive vault construction
    ///
    /// ```rust
    /// # use bitcoin::hashes::Hash;
    /// # use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
    /// # use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
    /// # use bitcoin::taproot::{LeafVersion, TapNodeHash};
    /// # use bitcoin::{absolute, Amount, blockdata::transaction, consensus::Encodable, Opcode, OutPoint, ScriptBuf, Sequence, Transaction, Txid, TxIn, TxOut, Witness};
    /// use bip119::{DefaultCheckTemplateVerifyHash, OP_CHECKTEMPLATEVERIFY};
    ///
    /// # let secp = Secp256k1::new();
    /// let cold_key = XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap();
    /// let spending_key = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    ///
    /// # const PAY_TO_ANCHOR_SCRIPT_BYTES: &[u8] = &[0x51, 0x02, 0x4e, 0x73];
    /// # let anchor_script_pubkey = ScriptBuf::from_bytes(PAY_TO_ANCHOR_SCRIPT_BYTES.to_vec());
    ///
    /// let dummy_prevout = OutPoint {
    ///     txid: Txid::from_byte_array([0u8; 32]),
    ///     vout: 0,
    /// };
    ///
    /// let anchor_output = TxOut {
    ///     value: Amount::ZERO,
    ///     script_pubkey: anchor_script_pubkey,
    /// };
    ///
    /// let clawback_template = Transaction {
    ///     version: transaction::Version::non_standard(3),
    ///     lock_time: absolute::LockTime::ZERO,
    ///     input: vec![
    ///         TxIn {
    ///             previous_output: dummy_prevout,
    ///             sequence: Sequence::ZERO,
    ///             script_sig: ScriptBuf::new(),
    ///             witness: Witness::new(),
    ///         },
    ///     ],
    ///     output: vec![
    ///         TxOut {
    ///             value: Amount::from_sat(100_000_000),
    ///             script_pubkey: ScriptBuf::new_p2tr(&secp, cold_key, None),
    ///         },
    ///         anchor_output.clone(),
    ///     ],
    /// };
    ///
    /// let clawback_template_hash =
    ///     DefaultCheckTemplateVerifyHash::from_transaction(&clawback_template, 0);
    /// let mut clawback_script = ScriptBuf::new();
    /// clawback_script.push_slice(clawback_template_hash);
    /// clawback_script.push_opcode(OP_CHECKTEMPLATEVERIFY);
    /// // We don't have to drop since the template hash is nonzero, this satisfies cleanstack
    ///
    /// let mut spending_script = ScriptBuf::new();
    /// spending_script.push_slice(&[36u8]); // 36 blocks
    /// spending_script.push_opcode(OP_CSV);
    /// spending_script.push_opcode(OP_DROP);
    /// spending_script.push_slice(&spending_key.serialize());
    /// spending_script.push_opcode(OP_CHECKSIG);
    ///
    /// let clawback_tap_node_hash = TapNodeHash::from_script(&clawback_script, LeafVersion::TapScript);
    /// let spending_tap_node_hash = TapNodeHash::from_script(&spending_script, LeafVersion::TapScript);
    ///
    /// let merkle_root = TapNodeHash::from_node_hashes(clawback_tap_node_hash, spending_tap_node_hash);
    ///
    /// // This script_pubkey can immediately be spent by the cold key,
    /// // be spent by the spending_key after a 36 block delay, or
    /// // clawed back to only be spendable by the cold key, but with no need
    /// // to bring the cold keys online.
    ///
    /// let withdrawal_script_pubkey = ScriptBuf::new_p2tr(&secp, cold_key, Some(merkle_root));
    ///
    /// let withdrawal_template = Transaction {
    ///     version: transaction::Version::non_standard(3),
    ///     lock_time: absolute::LockTime::ZERO,
    ///     input: vec![
    ///         TxIn {
    ///             previous_output: dummy_prevout,
    ///             sequence: Sequence::ZERO,
    ///             script_sig: ScriptBuf::new(),
    ///             witness: Witness::new(),
    ///         },
    ///     ],
    ///     output: vec![
    ///         TxOut {
    ///             value: Amount::from_sat(100_000_000),
    ///             script_pubkey: ScriptBuf::new_p2tr(&secp, cold_key, None),
    ///         },
    ///         anchor_output,
    ///     ],
    /// };
    ///
    /// // this hash commits to being the first input to the withdrawal_tx
    /// let withdrawal_template_hash =
    ///     DefaultCheckTemplateVerifyHash::from_transaction(&withdrawal_template, 0);
    ///
    /// let mut withdrawal_script = ScriptBuf::new();
    /// clawback_script.push_slice(withdrawal_template_hash);
    /// clawback_script.push_opcode(OP_CHECKTEMPLATEVERIFY);
    ///
    /// // This vault output can either be spent by the cold_key, or spent by the
    /// // withdrawal_template. The withdrawal template's output can then be spent
    /// // by the cold key, the spending_key after a 36 block delay, or spent
    /// // by the clawback_template which has its own output which is locked to
    /// // only the cold_key
    ///
    /// let vault_script_pubkey = ScriptBuf::new_p2tr(
    ///     &secp,
    ///     cold_key,
    ///     Some(TapNodeHash::from_script(&withdrawal_script, LeafVersion::TapScript)),
    /// );
    ///
    /// ```
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
    ///
    /// Rather than creating a [`bitcoin::Transaction`] and hashing it, code that
    /// wants to squeeze a bit of extra performance out of this library can
    /// call this function directly. In a [reasonable benchmark](https://github.com/Ademan/rust-bip119-bench),
    /// [`Self::from_components`] was ~31% faster than [`Self::from_transaction`].
    /// This will have a negligible impact on the runtime of most applications,
    /// however, applications that generate large numbers of recursive CTV
    /// commitments can potentially reap a substantial benefit.
    /// The convenience functions [`hash_sequences`], [`hash_script_sigs`], and
    /// [`hash_outputs`] are intended to simplify this process, however even
    /// more allocations can be avoided by computing `script_sig_sha256` and `outputs_sha256`
    /// manually.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitcoin::hashes::{Hash, HashEngine, sha256};
    /// # use bitcoin::opcodes::all::OP_PUSHBYTES_32;
    /// # use bitcoin::secp256k1::XOnlyPublicKey;
    /// # use bitcoin::{absolute, Amount, blockdata::transaction, consensus::Encodable, io::Write, Opcode, Sequence, WitnessVersion};
    /// use bip119::{DefaultCheckTemplateVerifyHash, hash_sequences};
    ///
    /// let sequences = [Sequence::ZERO, Sequence::ZERO, Sequence::from_height(42)];
    ///
    /// let outputs = [
    ///     (Amount::from_sat(42_000), XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap()),
    ///     (Amount::from_sat(999_999), XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap()),
    /// ];
    ///
    /// let sequences_sha256 = hash_sequences(sequences.iter().cloned());
    ///
    /// let outputs_sha256 = {
    ///     let mut sha256 = sha256::Hash::engine();
    ///
    ///     let taproot_script_pubkey_len = 1 + 1 + 32;
    ///     let segwit_v1_opcode = Opcode::from(WitnessVersion::V1).to_u8();
    ///     let taproot_script_prefix = [
    ///         taproot_script_pubkey_len,
    ///         segwit_v1_opcode,
    ///         OP_PUSHBYTES_32.to_u8(),
    ///     ];
    ///
    ///     for (amount, pubkey) in outputs {
    ///         // [`Encodable::consensus_encode`] will never fail unless the underlying
    ///         // [`Write::write`] fails.
    ///         // [`HashEngine`] writes never fail.
    ///         amount.consensus_encode(&mut sha256).unwrap();
    ///         sha256.write(&taproot_script_prefix).unwrap();
    ///         sha256.write(&pubkey.serialize()).unwrap();
    ///     }
    ///
    ///     sha256::Hash::from_engine(sha256)
    /// };
    ///
    /// let ctv_hash = DefaultCheckTemplateVerifyHash::from_components(
    ///     transaction::Version::ONE,
    ///     absolute::LockTime::ZERO,
    ///     sequences.len() as u32, // input count
    ///     None, // No script sigs
    ///     sequences_sha256,
    ///     outputs.len() as u32, // output count
    ///     outputs_sha256,
    ///     0, // First input
    /// );
    ///
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn from_components(
        version: Version,
        lock_time: absolute::LockTime,
        vin_count: u32,
        script_sig_sha256: Option<sha256::Hash>,
        sequences_sha256: sha256::Hash,
        vout_count: u32,
        outputs_sha256: sha256::Hash,
        input_index: u32,
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
