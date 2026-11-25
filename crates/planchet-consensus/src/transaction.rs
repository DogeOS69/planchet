//! Owned legacy transactions. Decoding delegates to the shared borrowed parser.
//!
//! Output values retain their wire bits. [`PaymentBudget`] is the separate
//! payment-policy boundary which rejects negative amounts and arithmetic overflow.
use alloc::{collections::BTreeSet, vec::Vec};
use core::fmt;
use planchet_primitives::{FeeRate, OutPoint, Txid, sha256d};

use crate::{DecodeError, DecodeLimits, TxRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxOut {
    /// Raw wire bits; values above `i64::MAX` are not valid payment amounts.
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    pub fn encode_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.value.to_le_bytes());
        encode_compact_size(self.script_pubkey.len() as u64, bytes);
        bytes.extend_from_slice(&self.script_pubkey);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode_to(&mut bytes);
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    pub fn decode_exact(bytes: &[u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        Ok(Self::from_ref(TxRef::decode_exact(bytes, limits)?))
    }

    /// PSBT's non-witness unsigned encoding, which also permits zero inputs.
    pub fn decode_unsigned_exact(bytes: &[u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        Ok(Self::from_ref(TxRef::decode_unsigned_exact(bytes, limits)?))
    }

    pub fn from_ref(tx: TxRef<'_>) -> Self {
        Self {
            version: tx.version(),
            inputs: tx
                .inputs()
                .map(|input| TxIn {
                    previous_output: OutPoint::new(input.previous_txid(), input.vout()),
                    script_sig: input.script_sig().into(),
                    sequence: input.sequence(),
                })
                .collect(),
            outputs: tx
                .outputs()
                .map(|output| TxOut {
                    value: output.value(),
                    script_pubkey: output.script_pubkey().into(),
                })
                .collect(),
            lock_time: tx.lock_time(),
        }
    }

    pub fn encode_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.version.to_le_bytes());
        encode_compact_size(self.inputs.len() as u64, bytes);
        for input in &self.inputs {
            bytes.extend_from_slice(input.previous_output.txid.as_wire_bytes());
            bytes.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            encode_compact_size(input.script_sig.len() as u64, bytes);
            bytes.extend_from_slice(&input.script_sig);
            bytes.extend_from_slice(&input.sequence.to_le_bytes());
        }
        encode_compact_size(self.outputs.len() as u64, bytes);
        for output in &self.outputs {
            output.encode_to(bytes);
        }
        bytes.extend_from_slice(&self.lock_time.to_le_bytes());
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode_to(&mut bytes);
        bytes
    }

    /// Hash the actual transaction, including each original scriptSig.
    pub fn txid(&self) -> Txid {
        Txid::from_wire_bytes(sha256d(&self.encode()))
    }

    pub fn builder(version: i32, lock_time: u32) -> TransactionBuilder {
        TransactionBuilder(Self {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time,
        })
    }
}

pub struct TransactionBuilder(Transaction);

impl TransactionBuilder {
    pub fn spend(mut self, previous_output: OutPoint, sequence: u32) -> Self {
        self.0.inputs.push(TxIn {
            previous_output,
            sequence,
            script_sig: Vec::new(),
        });
        self
    }

    pub fn pay(mut self, script_pubkey: impl Into<Vec<u8>>, value: u64) -> Self {
        self.0.outputs.push(TxOut {
            value,
            script_pubkey: script_pubkey.into(),
        });
        self
    }

    pub fn finish(self) -> Result<Transaction, PaymentError> {
        validate_payment_structure(&self.0)?;
        Ok(self.0)
    }
}

/// Canonical CompactSize encoding used by owned transactions and PSBT maps.
pub fn encode_compact_size(value: u64, bytes: &mut Vec<u8>) {
    let mut buffer = [0; 9];
    // The canonical encoder needs at most nine bytes for any u64.
    let size = crate::compact_size::encode_compact_size(value, &mut buffer)
        .expect("nine bytes cover every CompactSize");
    bytes.extend_from_slice(&buffer[..size]);
}

/// Explicitly supplied trusted output. Construction does not prove unspentness,
/// confirmations or chain membership; the caller authenticates those facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prevout {
    pub outpoint: OutPoint,
    pub output: TxOut,
}

impl Prevout {
    /// Recompute the parent ID and bind the index to an existing output.
    pub fn from_parent(outpoint: OutPoint, parent: &Transaction) -> Result<Self, PaymentError> {
        if parent.txid() != outpoint.txid {
            return Err(PaymentError::ParentTxidMismatch);
        }
        let output = parent
            .outputs
            .get(outpoint.vout as usize)
            .ok_or(PaymentError::MissingPrevout)?
            .clone();
        Ok(Self { outpoint, output })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentError {
    EmptyInputs,
    EmptyOutputs,
    DuplicateInput,
    NullOutpoint,
    MissingPrevout,
    PrevoutMismatch,
    ParentTxidMismatch,
    InvalidAmount,
    Overflow,
    InsufficientFunds,
    FeeExceedsBudget,
    FeeRateTooLow,
}

impl fmt::Display for PaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for PaymentError {}

/// Caller-authorized fee ceiling and minimum rate, in koinu per 1000 bytes.
/// This is a payment budget, not a claim about a node's relay policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentBudget {
    pub max_fee: u64,
    pub min_fee_rate_koinu_per_kvb: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaymentSummary {
    pub input_value: u64,
    pub output_value: u64,
    pub fee: u64,
    pub required_fee: u64,
    pub transaction_bytes: usize,
}

fn checked_amount(value: u64) -> Result<u64, PaymentError> {
    if value > i64::MAX as u64 {
        Err(PaymentError::InvalidAmount)
    } else {
        Ok(value)
    }
}

fn validate_payment_structure(tx: &Transaction) -> Result<(), PaymentError> {
    if tx.inputs.is_empty() {
        return Err(PaymentError::EmptyInputs);
    }
    if tx.outputs.is_empty() {
        return Err(PaymentError::EmptyOutputs);
    }
    let mut seen = BTreeSet::new();
    for input in &tx.inputs {
        if input.previous_output.is_null() {
            return Err(PaymentError::NullOutpoint);
        }
        if !seen.insert(input.previous_output) {
            return Err(PaymentError::DuplicateInput);
        }
    }
    tx.outputs.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(checked_amount(output.value)?)
            .ok_or(PaymentError::Overflow)
    })?;
    Ok(())
}

impl PaymentBudget {
    /// Prevouts must be in input order, with exactly one trusted output per input.
    pub fn check(
        &self,
        tx: &Transaction,
        prevouts: &[Prevout],
        transaction_bytes: usize,
    ) -> Result<PaymentSummary, PaymentError> {
        validate_payment_structure(tx)?;
        if prevouts.len() != tx.inputs.len() {
            return Err(PaymentError::MissingPrevout);
        }
        let mut input_value = 0u64;
        for (input, prevout) in tx.inputs.iter().zip(prevouts) {
            if input.previous_output != prevout.outpoint {
                return Err(PaymentError::PrevoutMismatch);
            }
            input_value = input_value
                .checked_add(checked_amount(prevout.output.value)?)
                .ok_or(PaymentError::Overflow)?;
        }
        let output_value = tx.outputs.iter().try_fold(0u64, |sum, output| {
            sum.checked_add(output.value).ok_or(PaymentError::Overflow)
        })?;
        let fee = input_value
            .checked_sub(output_value)
            .ok_or(PaymentError::InsufficientFunds)?;
        if fee > self.max_fee {
            return Err(PaymentError::FeeExceedsBudget);
        }
        let size = u64::try_from(transaction_bytes).map_err(|_| PaymentError::Overflow)?;
        let required_fee = FeeRate::from_koinu_per_kvb(self.min_fee_rate_koinu_per_kvb)
            .fee_for_bytes(size)
            .ok_or(PaymentError::Overflow)?
            .to_koinu();
        if fee < required_fee {
            return Err(PaymentError::FeeRateTooLow);
        }
        Ok(PaymentSummary {
            input_value,
            output_value,
            fee,
            required_fee,
            transaction_bytes,
        })
    }
}
