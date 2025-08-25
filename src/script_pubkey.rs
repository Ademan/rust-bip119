//! Helpers for handling scriptPubkeys without allocations

use bitcoin::{WPubkeyHash, WScriptHash, ScriptHash};
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedPublicKey};
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_PUSHBYTES_0 as OP_0, OP_CHECKSIG, OP_EQUAL, OP_EQUALVERIFY, OP_DUP, OP_HASH160, OP_PUSHBYTES_32, OP_PUSHNUM_1};
use bitcoin::secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE;
use bitcoin::secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::{Amount, consensus::Encodable, PubkeyHash, PublicKey, ScriptBuf, taproot::TapNodeHash};

const OP_PUSHDATA_X_LEN: u8 = 1;
const OP_CHECKSIG_LEN: u8 = 1;
const OP_DUP_LEN: u8 = 1;
const OP_HASH160_LEN: u8 = 1;
const OP_EQUALVERIFY_LEN: u8 = 1;
const OP_EQUAL_LEN: u8 = 1;

/// Represents a Pay to Pubkey output with a given public key
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct PayToPubkey(PublicKey);

impl PayToPubkey {
    pub fn new_p2pk(pk: PublicKey) -> PayToPubkey {
        Self(pk)
    }
}

impl Encodable for PayToPubkey {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        if self.0.compressed {
            let p2pk = self.0.inner.serialize();
            let p2pk_len: u8 = p2pk.len().try_into().expect("pubkey len fits into u8");
            let p2pk_scriptbuf_len = OP_PUSHDATA_X_LEN + p2pk_len + OP_CHECKSIG_LEN;

            let mut len = writer.write(&[p2pk_scriptbuf_len, p2pk_len])?;
            len += writer.write(&p2pk)?;
            len += writer.write(&[OP_CHECKSIG.to_u8()])?;

            Ok(len)
        } else {
            let p2pk = self.0.inner.serialize_uncompressed();
            let p2pk_len: u8 = p2pk.len().try_into().expect("pubkey len fits into u8");
            let p2pk_scriptbuf_len = OP_PUSHDATA_X_LEN + p2pk_len + OP_CHECKSIG_LEN;

            let mut len = writer.write(&[p2pk_scriptbuf_len, p2pk_len])?;
            len += writer.write(&p2pk)?;
            len += writer.write(&[OP_CHECKSIG.to_u8()])?;

            Ok(len)
        }
    }
}

impl From<PayToPubkey> for ScriptBuf {
    fn from(p2pk: PayToPubkey) -> Self {
        if p2pk.0.compressed {
            let p2pk = p2pk.0.inner.serialize();
            let mut script_pubkey = ScriptBuf::with_capacity(1 + 1 + p2pk.len());

            script_pubkey.push_slice(p2pk);
            script_pubkey.push_opcode(OP_CHECKSIG);

            script_pubkey
        } else {
            let p2pk = p2pk.0.inner.serialize_uncompressed();
            let mut script_pubkey = ScriptBuf::with_capacity(1 + 1 + p2pk.len());

            script_pubkey.push_slice(p2pk);
            script_pubkey.push_opcode(OP_CHECKSIG);

            script_pubkey
        }
    }
}

/// Represents a Pay to Pubkey Hash output with a given public key
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct PayToPubkeyHash(bitcoin::PubkeyHash);

impl PayToPubkeyHash {
    pub fn new_p2pkh(pkh: bitcoin::PubkeyHash) -> Self {
        Self(pkh)
    }
}

const PAY_TO_PUBKEY_HASH_SCRIPT_LEN: u8 =
            OP_DUP_LEN +
            OP_HASH160_LEN +
            OP_PUSHDATA_X_LEN +
            PubkeyHash::LEN as u8 +
            OP_EQUALVERIFY_LEN +
            OP_CHECKSIG_LEN;

impl Encodable for PayToPubkeyHash {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        let pkh = self.0.to_byte_array();

        let mut len = writer.write(&[
            PAY_TO_PUBKEY_HASH_SCRIPT_LEN,
            OP_DUP.to_u8(),
            OP_HASH160.to_u8(),
            PubkeyHash::LEN as u8,
        ])?;
        len += writer.write(&pkh)?;
        len += writer.write(&[
            OP_EQUALVERIFY.to_u8(),
            OP_CHECKSIG.to_u8(),
        ])?;

        Ok(len)
    }
}

impl From<PayToPubkeyHash> for ScriptBuf {
    fn from(p2pkh: PayToPubkeyHash) -> Self {
        let pkh = p2pkh.0.to_byte_array();

        let mut script_pubkey = ScriptBuf::with_capacity(PAY_TO_PUBKEY_HASH_SCRIPT_LEN as usize);

        script_pubkey.push_opcode(OP_DUP);
        script_pubkey.push_opcode(OP_HASH160);
        script_pubkey.push_slice(pkh);
        script_pubkey.push_opcode(OP_EQUALVERIFY);
        script_pubkey.push_opcode(OP_CHECKSIG);
        script_pubkey
    }
}

/// Represents a Pay to Script Hash output with a given script hash
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct PayToScriptHash(ScriptHash);

impl PayToScriptHash {
    pub fn new_p2sh(sh: ScriptHash) -> Self {
        Self(sh)
    }
}

const PAY_TO_SCRIPT_HASH_SCRIPT_LEN: u8 =
            OP_HASH160_LEN +
            OP_PUSHDATA_X_LEN +
            ScriptHash::LEN as u8 +
            OP_EQUAL_LEN;

impl Encodable for PayToScriptHash {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        let sh = self.0.to_byte_array();

        let mut len = writer.write(&[
            PAY_TO_SCRIPT_HASH_SCRIPT_LEN,
            OP_HASH160.to_u8(),
            ScriptHash::LEN as u8,
        ])?;
        len += writer.write(&sh)?;
        len += writer.write(&[
            OP_EQUAL.to_u8(),
        ])?;

        Ok(len)
    }
}

impl From<PayToScriptHash> for ScriptBuf {
    fn from(p2sh: PayToScriptHash) -> Self {
        let sh = p2sh.0.to_byte_array();

        let mut script_pubkey = ScriptBuf::with_capacity(PAY_TO_SCRIPT_HASH_SCRIPT_LEN as usize);

        script_pubkey.push_opcode(OP_HASH160);
        script_pubkey.push_slice(sh);
        script_pubkey.push_opcode(OP_EQUAL);
        script_pubkey
    }
}

/// Represents a Pay to Witness Pubkey Hash output with a given public key hash
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct PayToWitnessPubkeyHash(WPubkeyHash);

impl PayToWitnessPubkeyHash {
    pub fn new_p2wpkh(wpkh: WPubkeyHash) -> Self {
        Self(wpkh)
    }
}

const WITNESS_V0_LEN: u8 = 1;
const WITNESS_V0: u8 = 0;
const PAY_TO_WITNESS_PUBKEY_HASH_LEN: u8 =
    WITNESS_V0_LEN +
    OP_PUSHDATA_X_LEN +
    WPubkeyHash::LEN as u8;

impl Encodable for PayToWitnessPubkeyHash {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        let wpkh = self.0.to_byte_array();

        let mut len = writer.write(&[
            PAY_TO_WITNESS_PUBKEY_HASH_LEN,
            WITNESS_V0,
            WPubkeyHash::LEN as u8,
        ])?;
        len += writer.write(&wpkh)?;

        Ok(len)
    }
}

impl From<PayToWitnessPubkeyHash> for ScriptBuf {
    fn from(p2wpkh: PayToWitnessPubkeyHash) -> Self {
        let wpkh = p2wpkh.0.to_byte_array();

        let mut script_pubkey = ScriptBuf::with_capacity(PAY_TO_WITNESS_PUBKEY_HASH_LEN as usize);

        script_pubkey.push_opcode(OP_0);
        script_pubkey.push_slice(wpkh);
        script_pubkey
    }
}

/// Represents a Pay to Witness Script Hash output with a given script hash
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct PayToWitnessScriptHash(WScriptHash);

impl PayToWitnessScriptHash {
    pub fn new_p2wsh(wpkh: WScriptHash) -> Self {
        Self(wpkh)
    }
}

const PAY_TO_WITNESS_SCRIPT_HASH_LEN: u8 =
    WITNESS_V0_LEN +
    OP_PUSHDATA_X_LEN +
    WScriptHash::LEN as u8;

impl Encodable for PayToWitnessScriptHash {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        let wsh = self.0.to_byte_array();

        let mut len = writer.write(&[
            PAY_TO_WITNESS_SCRIPT_HASH_LEN,
            WITNESS_V0,
            WScriptHash::LEN as u8,
        ])?;
        len += writer.write(&wsh)?;

        Ok(len)
    }
}

impl From<PayToWitnessScriptHash> for ScriptBuf {
    fn from(p2wsh: PayToWitnessScriptHash) -> Self {
        let wsh = p2wsh.0.to_byte_array();

        let mut script_pubkey = ScriptBuf::with_capacity(PAY_TO_WITNESS_SCRIPT_HASH_LEN as usize);

        script_pubkey.push_opcode(OP_0);
        script_pubkey.push_slice(wsh);
        script_pubkey
    }
}

const WITNESS_V1_LEN: u8 = 1;
const WITNESS_V1: u8 = 0x51; // OP_PUSHNUM_1
const PUSHBYTES_32_LEN: u8 = 1;
const TAPROOT_SCRIPT_PUBKEY_LEN: u8 = WITNESS_V1_LEN + PUSHBYTES_32_LEN + SCHNORR_PUBLIC_KEY_SIZE as u8;

/// Represents a Pay to Taproot output with a given output public key
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct PayToTaproot(TweakedPublicKey);

impl PayToTaproot {
    pub fn new_p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: XOnlyPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let (output_key, _) = internal_key.tap_tweak(secp, merkle_root);

        Self::new_p2tr_tweaked(output_key)
    }

    pub fn new_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        Self(output_key)
    }
}

impl Encodable for PayToTaproot {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        const TAPROOT_SCRIPT_PREFIX: [u8; 3] = [
            TAPROOT_SCRIPT_PUBKEY_LEN,
            WITNESS_V1,
            OP_PUSHBYTES_32.to_u8(),
        ];

        let mut len = writer.write(&TAPROOT_SCRIPT_PREFIX)?;
        len += writer.write(&self.0.serialize())?;

        Ok(len)
    }
}

impl From<PayToTaproot> for ScriptBuf {
    fn from(value: PayToTaproot) -> Self {
        let mut script_pubkey = ScriptBuf::with_capacity(TAPROOT_SCRIPT_PUBKEY_LEN as usize);
        script_pubkey.push_opcode(OP_PUSHNUM_1);
        script_pubkey.push_slice(value.0.serialize());

        script_pubkey
    }
}

pub const PAY_TO_ANCHOR_SCRIPT_BYTES: &[u8] = &[0x51, 0x02, 0x4e, 0x73];
const PAY_TO_ANCHOR_SCRIPT_LEN: u8 = PAY_TO_ANCHOR_SCRIPT_BYTES.len() as u8;

/// Represents a pay to anchor output
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct PayToAnchor;

impl Encodable for PayToAnchor {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = writer.write(&[PAY_TO_ANCHOR_SCRIPT_LEN])?;
        len += writer.write(PAY_TO_ANCHOR_SCRIPT_BYTES)?;

        Ok(len)
    }
}

impl From<PayToAnchor> for ScriptBuf {
    fn from(_p2a: PayToAnchor) -> Self {
        ScriptBuf::from_bytes(PAY_TO_ANCHOR_SCRIPT_BYTES.to_vec())
    }
}

/// Represents any of several common output types
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum ScriptPubkey {
    PayToPubkey(PayToPubkey),
    PayToPubkeyHash(PayToPubkeyHash),
    PayToScriptHash(PayToScriptHash),
    PayToWitnessPubkeyHash(PayToWitnessPubkeyHash),
    PayToWitnessScriptHash(PayToWitnessScriptHash),
    PayToTaproot(PayToTaproot),
    PayToAnchor(PayToAnchor),
}

impl ScriptPubkey {
    /// Generates P2PK-type of scriptPubkey.
    pub fn new_p2pk(pubkey: PublicKey) -> Self {
        Self::PayToPubkey(PayToPubkey::new_p2pk(pubkey))
    }

    /// Generates P2PKH-type of scriptPubkey.
    pub fn new_p2pkh(pubkey_hash: PubkeyHash) -> Self {
        Self::PayToPubkeyHash(PayToPubkeyHash::new_p2pkh(pubkey_hash))
    }

    /// Generates P2SH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_p2sh(script_hash: ScriptHash) -> Self {
        Self::PayToScriptHash(PayToScriptHash::new_p2sh(script_hash))
    }

    /// Generates P2WPKH-type of scriptPubkey.
    pub fn new_p2wpkh(pubkey_hash: WPubkeyHash) -> Self {
        Self::PayToWitnessPubkeyHash(PayToWitnessPubkeyHash::new_p2wpkh(pubkey_hash))
    }

    /// Generates P2WSH-type of scriptPubkey with a given hash of the redeem script.
    pub fn new_p2wsh(script_hash: WScriptHash) -> Self {
        Self::PayToWitnessScriptHash(PayToWitnessScriptHash::new_p2wsh(script_hash))
    }

    /// Generates P2TR for script spending path using an internal public key and some optional
    /// script tree merkle root.
    pub fn new_p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        Self::PayToTaproot(PayToTaproot::new_p2tr(secp, internal_key, merkle_root))
    }

    /// Generates P2TR for key spending path for a known [`TweakedPublicKey`].
    pub fn new_p2tr_tweaked(output_key: TweakedPublicKey) -> Self {
        Self::PayToTaproot(PayToTaproot::new_p2tr_tweaked(output_key))
    }

    /// Generates P2A Pay to Anchor
    pub fn new_p2a() -> Self {
        Self::PayToAnchor(PayToAnchor)
    }
}

impl Encodable for ScriptPubkey {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        match self {
            ScriptPubkey::PayToPubkey(p2pk) => p2pk.consensus_encode(writer),
            ScriptPubkey::PayToPubkeyHash(p2pkh) => p2pkh.consensus_encode(writer),
            ScriptPubkey::PayToScriptHash(p2sh) => p2sh.consensus_encode(writer),
            ScriptPubkey::PayToWitnessPubkeyHash(p2wpkh) => p2wpkh.consensus_encode(writer),
            ScriptPubkey::PayToWitnessScriptHash(p2wsh) => p2wsh.consensus_encode(writer),
            ScriptPubkey::PayToTaproot(p2tr) => p2tr.consensus_encode(writer),
            ScriptPubkey::PayToAnchor(p2a) => p2a.consensus_encode(writer),
        }
    }
}

impl From<&ScriptPubkey> for ScriptBuf {
    fn from(script_pubkey: &ScriptPubkey) -> Self {
        match script_pubkey {
            ScriptPubkey::PayToPubkey(p2pk) => ScriptBuf::from(*p2pk),
            ScriptPubkey::PayToPubkeyHash(p2pkh) => ScriptBuf::from(*p2pkh),
            ScriptPubkey::PayToScriptHash(p2sh) => ScriptBuf::from(*p2sh),
            ScriptPubkey::PayToWitnessPubkeyHash(p2wpkh) => ScriptBuf::from(*p2wpkh),
            ScriptPubkey::PayToWitnessScriptHash(p2wsh) => ScriptBuf::from(*p2wsh),
            ScriptPubkey::PayToTaproot(p2tr) => ScriptBuf::from(*p2tr),
            ScriptPubkey::PayToAnchor(p2a) => ScriptBuf::from(*p2a),
        }
    }
}

/// Represents a transaction output
/// It is provided to be a convenient, near drop-in replacement for
/// [`bitcoin::TxOut`] usable with [`ScriptPubkey`] which provides a compact,
/// Copy-able data structure that does not require allocations like
/// [`bitcoin::ScriptBuf`] does. It can be used with [`crate::hash_outputs`]
/// and [`crate::DefaultCheckTemplateVerifyHash::from_components`] to calculate a
/// `OP_CHECKTEMPLATEVERIFY` hash without allocations.
#[derive(Clone, Copy, Debug)]
pub struct TxOut<S> {
    pub value: Amount,
    pub script_pubkey: S,
}

impl<S: Encodable> Encodable for TxOut<S> {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = self.value.consensus_encode(writer)?;
        len += self.script_pubkey.consensus_encode(writer)?;

        Ok(len)
    }
}

impl<S: Into<ScriptBuf>> From<TxOut<S>> for bitcoin::TxOut {
    fn from(txout: TxOut<S>) -> Self {
        bitcoin::TxOut {
            value: txout.value,
            script_pubkey: txout.script_pubkey.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{hash_outputs, hash_sequences, DefaultCheckTemplateVerifyHash};

    use bitcoin::{blockdata::locktime::absolute, CompressedPublicKey, hashes::{Hash, sha256}, OutPoint, secp256k1::Parity, Sequence, transaction, Transaction, Txid, TxIn, Witness};
    use bitcoin::secp256k1;

    fn hash_encodable<E: Encodable>(encodable: E) -> sha256::Hash {
        let mut sha256 = sha256::Hash::engine();

        encodable.consensus_encode(&mut sha256).unwrap();

        sha256::Hash::from_engine(sha256)
    }

    #[test]
    fn test_p2pk_equivalence() {
        let pubkey = secp256k1::PublicKey::from_x_only_public_key(
            XOnlyPublicKey::from_slice(&[42u8; 32]).unwrap(),
            Parity::Even,
        );

        let pk = bitcoin::PublicKey::new(pubkey);

        let p2pk = PayToPubkey(pk);
        let p2pk_scriptbuf = ScriptBuf::new_p2pk(&pk);

        assert_eq!(
            ScriptBuf::from(p2pk),
            p2pk_scriptbuf,
        );

        assert_eq!(
            hash_encodable(&p2pk),
            hash_encodable(&p2pk_scriptbuf),
        );

        let pk_uncompressed = bitcoin::PublicKey::new_uncompressed(pubkey);

        let p2pk_uncompressed = PayToPubkey::new_p2pk(pk_uncompressed);
        let p2pk_scriptbuf_uncompressed = ScriptBuf::new_p2pk(&pk_uncompressed);

        assert_eq!(
            ScriptBuf::from(p2pk_uncompressed),
            p2pk_scriptbuf_uncompressed,
        );

        assert_eq!(
            hash_encodable(&p2pk_uncompressed),
            hash_encodable(&p2pk_scriptbuf_uncompressed),
        );
    }

    #[test]
    fn test_p2pkh_equivalence() {
        let pubkey = secp256k1::PublicKey::from_x_only_public_key(
            XOnlyPublicKey::from_slice(&[42u8; 32]).unwrap(),
            Parity::Even,
        );

        let pk = bitcoin::PublicKey::new(pubkey);
        let pkh = PubkeyHash::from(pk);

        let p2pkh = PayToPubkeyHash::new_p2pkh(pkh);
        let p2pkh_scriptbuf = ScriptBuf::new_p2pkh(&pkh);

        assert_eq!(
            ScriptBuf::from(p2pkh),
            p2pkh_scriptbuf,
        );

        assert_eq!(
            hash_encodable(&p2pkh),
            hash_encodable(&p2pkh_scriptbuf),
        );
    }

    #[test]
    fn test_p2sh_equivalence() {
        let pubkey = secp256k1::PublicKey::from_x_only_public_key(
            XOnlyPublicKey::from_slice(&[42u8; 32]).unwrap(),
            Parity::Even,
        );

        let mut script = ScriptBuf::new();
        script.push_slice(&pubkey.serialize());
        script.push_opcode(OP_CHECKSIG);

        let sh = ScriptHash::from(script);

        let p2sh = PayToScriptHash::new_p2sh(sh);
        let p2sh_scriptbuf = ScriptBuf::new_p2sh(&sh);

        assert_eq!(
            ScriptBuf::from(p2sh),
            p2sh_scriptbuf,
        );

        assert_eq!(
            hash_encodable(&p2sh),
            hash_encodable(&p2sh_scriptbuf),
        );
    }

    #[test]
    fn test_p2wpkh_equivalence() {
        let pubkey = secp256k1::PublicKey::from_x_only_public_key(
            XOnlyPublicKey::from_slice(&[42u8; 32]).unwrap(),
            Parity::Even,
        );
        let pk = CompressedPublicKey(pubkey);
        let wpkh = WPubkeyHash::from(pk);

        let p2wpkh = PayToWitnessPubkeyHash(wpkh);
        let p2wpkh_scriptbuf = ScriptBuf::new_p2wpkh(&wpkh);

        assert_eq!(
            ScriptBuf::from(p2wpkh),
            p2wpkh_scriptbuf,
        );

        assert_eq!(
            hash_encodable(&p2wpkh),
            hash_encodable(&p2wpkh_scriptbuf),
        );
    }

    #[test]
    fn test_p2wsh_equivalence() {
        let pubkey = secp256k1::PublicKey::from_x_only_public_key(
            XOnlyPublicKey::from_slice(&[42u8; 32]).unwrap(),
            Parity::Even,
        );

        let mut script = ScriptBuf::new();
        script.push_slice(&pubkey.serialize());
        script.push_opcode(OP_CHECKSIG);

        let wsh = WScriptHash::from(script);

        let p2wsh = PayToWitnessScriptHash(wsh);
        let p2wsh_scriptbuf = ScriptBuf::new_p2wsh(&wsh);

        assert_eq!(
            ScriptBuf::from(p2wsh),
            p2wsh_scriptbuf,
        );

        assert_eq!(
            hash_encodable(&p2wsh),
            hash_encodable(&p2wsh_scriptbuf),
        );
    }

    #[test]
    fn test_p2tr_equivalence() {
        let output_key = TweakedPublicKey::dangerous_assume_tweaked(
            XOnlyPublicKey::from_slice(&[42u8; 32]).unwrap()
        );

        let p2tr = PayToTaproot::new_p2tr_tweaked(output_key);
        let p2tr_scriptbuf = ScriptBuf::new_p2tr_tweaked(output_key);

        assert_eq!(
            ScriptBuf::from(p2tr),
            p2tr_scriptbuf,
        );

        assert_eq!(
            hash_encodable(&p2tr),
            hash_encodable(&p2tr_scriptbuf),
        );
    }

    #[test]
    fn test_p2a_equivalence() {
        let p2a_scriptbuf = ScriptBuf::from_bytes(PAY_TO_ANCHOR_SCRIPT_BYTES.to_vec());

        assert_eq!(
            ScriptBuf::from(PayToAnchor),
            p2a_scriptbuf,
        );

        assert_eq!(
            hash_encodable(&PayToAnchor),
            hash_encodable(&p2a_scriptbuf),
        );
    }

    #[test]
    fn test_from_components_equivalence() {
        let dummy_prevout: OutPoint = OutPoint {
            txid: Txid::from_byte_array([0u8; 32]),
            vout: 0,
        };

        let a = TweakedPublicKey::dangerous_assume_tweaked(
            XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap()
        );

        let b = TweakedPublicKey::dangerous_assume_tweaked(
            XOnlyPublicKey::from_slice(&[42u8; 32]).unwrap()
        );

        let default_template_hash_from_transaction = {
            let transaction = Transaction {
                version: transaction::Version::non_standard(3),
                lock_time: absolute::LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: dummy_prevout,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ZERO,
                        witness: Witness::new(),
                    },
                    TxIn {
                        previous_output: dummy_prevout,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::ZERO,
                        witness: Witness::new(),
                    },
                ],
                output: vec![
                    bitcoin::TxOut {
                        value: Amount::from_sat(42),
                        script_pubkey: ScriptBuf::new_p2tr_tweaked(a),
                    },
                    bitcoin::TxOut {
                        value: Amount::from_sat(999),
                        script_pubkey: ScriptBuf::new_p2tr_tweaked(b),
                    },
                    bitcoin::TxOut {
                        value: Amount::ZERO,
                        script_pubkey: ScriptBuf::from_bytes(PAY_TO_ANCHOR_SCRIPT_BYTES.to_vec()),
                    },
                ],
            };

            DefaultCheckTemplateVerifyHash::from_transaction(&transaction, 0)
        };

        let default_template_hash_from_components = {
            DefaultCheckTemplateVerifyHash::from_components(
                transaction::Version::non_standard(3),
                absolute::LockTime::ZERO,
                2 /* vin_count */,
                None /* no script sigs */,
                hash_sequences([Sequence::ZERO, Sequence::ZERO]),
                3 /* vout_count */,
                hash_outputs([
                    TxOut {
                        value: Amount::from_sat(42),
                        script_pubkey: ScriptPubkey::new_p2tr_tweaked(a),
                    },
                    TxOut {
                        value: Amount::from_sat(999),
                        script_pubkey: ScriptPubkey::new_p2tr_tweaked(b),
                    },
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: ScriptPubkey::new_p2a(),
                    },
                ]),
                0 /* input_index */,
            )
        };

        assert_eq!(
            default_template_hash_from_transaction,
            default_template_hash_from_components,
        );
    }
}
