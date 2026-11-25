use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use core::fmt;
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use planchet_consensus::script::{match_p2pkh, push_data};
use planchet_consensus::sighash::{SighashError, SighashType, legacy_sighash_for_signing};
use planchet_consensus::transaction::{
    PaymentBudget, PaymentError, PaymentSummary, Prevout, Transaction, TxOut, encode_compact_size,
};
use planchet_consensus::{DecodeError, DecodeLimits, compact_size::decode_compact_size};
use planchet_primitives::{Sighash, hash160};

const MAGIC: &[u8] = b"psbt\xff";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Decode(DecodeError),
    Magic,
    Truncated,
    Limits,
    DuplicateKey,
    EmptyKey,
    InvalidKey,
    InvalidValue,
    MissingUnsignedTransaction,
    UnsupportedVersion,
    UnsignedScriptSig,
    MapCount,
    Conflict,
    DifferentTransaction,
    InputIndex,
    MissingUtxo,
    UtxoMismatch,
    UnsupportedTemplate,
    InvalidPublicKey,
    WrongPublicKey,
    InvalidSignature,
    HighS,
    SighashMismatch,
    StaleRequest,
    AlreadyFinalized,
    MissingSignature,
    InvalidFinalScript,
    Payment(PaymentError),
    Sighash(SighashError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}
impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}
impl From<PaymentError> for Error {
    fn from(e: PaymentError) -> Self {
        Self::Payment(e)
    }
}
impl From<SighashError> for Error {
    fn from(e: SighashError) -> Self {
        Self::Sighash(e)
    }
}

/// Application resource limits, checked before copying a map entry.
#[derive(Clone, Copy, Debug)]
pub struct PsbtLimits {
    pub max_bytes: usize,
    pub max_entries_per_map: usize,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub transaction: DecodeLimits,
}
impl Default for PsbtLimits {
    fn default() -> Self {
        Self {
            max_bytes: 16_000_000,
            max_entries_per_map: 10_000,
            max_key_bytes: 10_000,
            max_value_bytes: 4_000_000,
            transaction: DecodeLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyValue {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Ordered unique-key map. An untouched decoded PSBT encodes byte-for-byte.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawMap {
    entries: Vec<KeyValue>,
}
impl RawMap {
    pub fn entries(&self) -> &[KeyValue] {
        &self.entries
    }
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.value.as_slice())
    }
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        if key.is_empty() {
            return Err(Error::EmptyKey);
        }
        if let Some(existing) = self.get(&key) {
            return if existing == value {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.entries.push(KeyValue { key, value });
        Ok(())
    }
    fn encode_to(&self, bytes: &mut Vec<u8>) {
        for entry in &self.entries {
            encode_compact_size(entry.key.len() as u64, bytes);
            bytes.extend_from_slice(&entry.key);
            encode_compact_size(entry.value.len() as u64, bytes);
            bytes.extend_from_slice(&entry.value);
        }
        bytes.push(0);
    }
    fn merge(&mut self, other: &Self) -> Result<(), Error> {
        let existing: BTreeMap<&[u8], &[u8]> = self
            .entries
            .iter()
            .map(|entry| (entry.key.as_slice(), entry.value.as_slice()))
            .collect();
        let mut added = Vec::new();
        for entry in &other.entries {
            match existing.get(entry.key.as_slice()) {
                Some(value) if *value != entry.value => return Err(Error::Conflict),
                Some(_) => {}
                None => added.push(entry.clone()),
            }
        }
        self.entries.extend(added);
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(len).ok_or(Error::Limits)?;
        let result = self.bytes.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(result)
    }
    fn count(&mut self, max: usize) -> Result<usize, Error> {
        let (value, used) = decode_compact_size(&self.bytes[self.position..], max as u64)?;
        self.take(used)?;
        usize::try_from(value).map_err(|_| Error::Limits)
    }
    fn map(&mut self, limits: PsbtLimits, context: Context) -> Result<RawMap, Error> {
        let mut map = RawMap::default();
        let mut seen = BTreeSet::new();
        loop {
            let key_len = self.count(limits.max_key_bytes)?;
            if key_len == 0 {
                return Ok(map);
            }
            if map.entries.len() >= limits.max_entries_per_map {
                return Err(Error::Limits);
            }
            let key = self.take(key_len)?;
            if !seen.insert(key) {
                return Err(Error::DuplicateKey);
            }
            let value_len = self.count(limits.max_value_bytes)?;
            let value = self.take(value_len)?;
            validate_entry(key, value, context)?;
            map.entries.push(KeyValue {
                key: key.into(),
                value: value.into(),
            });
        }
    }
}

#[derive(Clone, Copy)]
enum Context {
    Global,
    Input,
    Output,
}

fn valid_public_key(key: &[u8]) -> Result<VerifyingKey, Error> {
    if !matches!((key.len(), key.first()), (33, Some(2 | 3)) | (65, Some(4))) {
        return Err(Error::InvalidPublicKey);
    }
    VerifyingKey::from_sec1_bytes(key).map_err(|_| Error::InvalidPublicKey)
}

fn validate_entry(key: &[u8], value: &[u8], context: Context) -> Result<(), Error> {
    let (kind, used) = decode_compact_size(key, u64::MAX)?;
    let data = &key[used..];
    let no_data = match context {
        Context::Global => matches!(kind, 0 | 0xfb),
        Context::Input => matches!(kind, 0 | 1 | 3 | 4 | 5 | 7 | 8),
        Context::Output => matches!(kind, 0 | 1),
    };
    if no_data && !data.is_empty() {
        return Err(Error::InvalidKey);
    }
    match (context, kind) {
        (Context::Global, 0xfb) => {
            if value.len() != 4 {
                return Err(Error::InvalidValue);
            }
            if value != [0; 4] {
                return Err(Error::UnsupportedVersion);
            }
        }
        (Context::Global, 1) => {
            if data.len() != 78 || value.len() < 4 || !value.len().is_multiple_of(4) {
                return Err(Error::InvalidKey);
            }
            valid_public_key(&data[45..])?;
        }
        (Context::Input, 2) => {
            valid_public_key(data)?;
        }
        (Context::Input, 6) | (Context::Output, 2) => {
            valid_public_key(data)?;
            if value.len() < 4 || !value.len().is_multiple_of(4) {
                return Err(Error::InvalidValue);
            }
        }
        (Context::Input, 3) => {
            if value.len() != 4 {
                return Err(Error::InvalidValue);
            }
        }
        // These fields remain opaque in the forwarding layer. Spending validates
        // their meaning and exact agreement with explicit trusted prevouts.
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PsbtV0 {
    unsigned: Transaction,
    global: RawMap,
    inputs: Vec<RawMap>,
    outputs: Vec<RawMap>,
}

/// Immutable request bound to an unsigned transaction, every trusted prevout,
/// the intended key, input, mode and caller's payment budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2pkhSignRequest {
    unsigned_bytes: Vec<u8>,
    prevouts: Vec<Prevout>,
    input_index: usize,
    public_key: Vec<u8>,
    sighash_type: SighashType,
    digest: Sighash,
    budget: PaymentBudget,
}
impl P2pkhSignRequest {
    pub fn digest(&self) -> Sighash {
        self.digest
    }
    pub fn input_index(&self) -> usize {
        self.input_index
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn sighash_type(&self) -> SighashType {
        self.sighash_type
    }
}

/// Only produced after script construction, ECDSA checks and actual-size budget
/// checks. Mutating the returned owned transaction requires explicit ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPayment {
    transaction: Transaction,
    summary: PaymentSummary,
}
impl SignedPayment {
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
    pub fn summary(&self) -> PaymentSummary {
        self.summary
    }
    pub fn encode(&self) -> Vec<u8> {
        self.transaction.encode()
    }
    pub fn into_transaction(self) -> Transaction {
        self.transaction
    }
}

impl PsbtV0 {
    pub fn decode(bytes: &[u8], limits: PsbtLimits) -> Result<Self, Error> {
        if bytes.len() > limits.max_bytes {
            return Err(Error::Limits);
        }
        let mut reader = Reader { bytes, position: 0 };
        if reader.take(5)? != MAGIC {
            return Err(Error::Magic);
        }
        let global = reader.map(limits, Context::Global)?;
        let raw_tx = global.get(&[0]).ok_or(Error::MissingUnsignedTransaction)?;
        let unsigned = Transaction::decode_unsigned_exact(raw_tx, limits.transaction)?;
        if unsigned
            .inputs
            .iter()
            .any(|input| !input.script_sig.is_empty())
        {
            return Err(Error::UnsignedScriptSig);
        }
        // Each remaining map has at least a one-byte terminator.
        let count = unsigned
            .inputs
            .len()
            .checked_add(unsigned.outputs.len())
            .ok_or(Error::Limits)?;
        if count > bytes.len().saturating_sub(reader.position) {
            return Err(Error::MapCount);
        }
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for _ in &unsigned.inputs {
            inputs.push(reader.map(limits, Context::Input)?);
        }
        for _ in &unsigned.outputs {
            outputs.push(reader.map(limits, Context::Output)?);
        }
        if reader.position != bytes.len() {
            return Err(Error::MapCount);
        }
        Ok(Self {
            unsigned,
            global,
            inputs,
            outputs,
        })
    }

    pub fn from_unsigned(unsigned: Transaction) -> Result<Self, Error> {
        if unsigned
            .inputs
            .iter()
            .any(|input| !input.script_sig.is_empty())
        {
            return Err(Error::UnsignedScriptSig);
        }
        let mut global = RawMap::default();
        global.insert(vec![0], unsigned.encode())?;
        let inputs = vec![RawMap::default(); unsigned.inputs.len()];
        let outputs = vec![RawMap::default(); unsigned.outputs.len()];
        Ok(Self {
            unsigned,
            global,
            inputs,
            outputs,
        })
    }
    pub fn unsigned_transaction(&self) -> &Transaction {
        &self.unsigned
    }
    pub fn global(&self) -> &RawMap {
        &self.global
    }
    pub fn inputs(&self) -> &[RawMap] {
        &self.inputs
    }
    pub fn outputs(&self) -> &[RawMap] {
        &self.outputs
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        self.global.encode_to(&mut bytes);
        for map in self.inputs.iter().chain(&self.outputs) {
            map.encode_to(&mut bytes);
        }
        bytes
    }

    /// Add metadata without replacing existing values, including unknown keys.
    /// The unsigned transaction is immutable; construct a new PSBT to change it.
    pub fn insert_global(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        validate_entry(&key, &value, Context::Global)?;
        self.global.insert(key, value)
    }
    pub fn insert_input(
        &mut self,
        index: usize,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), Error> {
        validate_entry(&key, &value, Context::Input)?;
        self.inputs
            .get_mut(index)
            .ok_or(Error::InputIndex)?
            .insert(key, value)
    }
    pub fn insert_output(
        &mut self,
        index: usize,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), Error> {
        validate_entry(&key, &value, Context::Output)?;
        self.outputs
            .get_mut(index)
            .ok_or(Error::MapCount)?
            .insert(key, value)
    }

    /// Atomic conflict rejection: no map is changed if any conflict exists.
    pub fn combine(&mut self, other: &Self) -> Result<(), Error> {
        if self.unsigned != other.unsigned {
            return Err(Error::DifferentTransaction);
        }
        let mut merged = self.clone();
        merged.global.merge(&other.global)?;
        for (left, right) in merged.inputs.iter_mut().zip(&other.inputs) {
            left.merge(right)?;
        }
        for (left, right) in merged.outputs.iter_mut().zip(&other.outputs) {
            left.merge(right)?;
        }
        *self = merged;
        Ok(())
    }

    pub fn attach_parent(&mut self, index: usize, parent: &Transaction) -> Result<(), Error> {
        let input = self.unsigned.inputs.get(index).ok_or(Error::InputIndex)?;
        let prevout = Prevout::from_parent(input.previous_output, parent)?;
        if let Some(compact) = self.inputs[index].get(&[1])
            && decode_txout(compact)? != prevout.output
        {
            return Err(Error::UtxoMismatch);
        }
        self.insert_input(index, vec![0], parent.encode())
    }

    /// Compact legacy use is explicit: the caller still authenticates this
    /// prevout from its trusted source at every signing/finalization boundary.
    pub fn attach_compact_prevout(&mut self, index: usize, prevout: &Prevout) -> Result<(), Error> {
        let input = self.unsigned.inputs.get(index).ok_or(Error::InputIndex)?;
        if input.previous_output != prevout.outpoint {
            return Err(Error::UtxoMismatch);
        }
        if let Some(parent) = self.inputs[index].get(&[0]) {
            let parent = Transaction::decode_exact(parent, DecodeLimits::default())?;
            if Prevout::from_parent(input.previous_output, &parent)?.output != prevout.output {
                return Err(Error::UtxoMismatch);
            }
        }
        self.insert_input(index, vec![1], prevout.output.encode())
    }

    fn check_prevouts(&self, prevouts: &[Prevout]) -> Result<(), Error> {
        if prevouts.len() != self.inputs.len() {
            return Err(PaymentError::MissingPrevout.into());
        }
        for ((input, map), trusted) in self.unsigned.inputs.iter().zip(&self.inputs).zip(prevouts) {
            if input.previous_output != trusted.outpoint {
                return Err(Error::UtxoMismatch);
            }
            if let Some(parent) = map.get(&[0]) {
                let parent = Transaction::decode_exact(parent, DecodeLimits::default())?;
                if Prevout::from_parent(input.previous_output, &parent)?.output != trusted.output {
                    return Err(Error::UtxoMismatch);
                }
            }
            if let Some(compact) = map.get(&[1])
                && decode_txout(compact)? != trusted.output
            {
                return Err(Error::UtxoMismatch);
            }
            // Missing embedded metadata is allowed only because a complete,
            // explicit trusted prevout is required by the public operation.
        }
        Ok(())
    }

    fn check_template(&self, index: usize, prevout: &Prevout, key: &[u8]) -> Result<(), Error> {
        valid_public_key(key)?;
        if match_p2pkh(&prevout.output.script_pubkey).map(|h| h.to_wire_bytes())
            != Some(hash160(key))
        {
            return Err(Error::UnsupportedTemplate);
        }
        let map = self.inputs.get(index).ok_or(Error::InputIndex)?;
        if map.get(&[4]).is_some() || map.get(&[5]).is_some() || map.get(&[8]).is_some() {
            return Err(Error::UnsupportedTemplate);
        }
        Ok(())
    }

    /// Preflight uses the largest low-S P2PKH scriptSig (including an
    /// uncompressed key) for every input. Final extraction checks actual bytes.
    pub fn sign_request(
        &self,
        input_index: usize,
        prevouts: &[Prevout],
        public_key: &[u8],
        sighash_type: SighashType,
        budget: PaymentBudget,
    ) -> Result<P2pkhSignRequest, Error> {
        self.check_prevouts(prevouts)?;
        let prevout = prevouts.get(input_index).ok_or(Error::InputIndex)?;
        self.check_template(input_index, prevout, public_key)?;
        let map = &self.inputs[input_index];
        if map.get(&[7]).is_some() {
            return Err(Error::AlreadyFinalized);
        }
        check_mode(map, sighash_type)?;
        let mut worst = self.unsigned.clone();
        for input in &mut worst.inputs {
            input.script_sig = vec![0; 139];
        }
        budget.check(&self.unsigned, prevouts, worst.encode().len())?;
        let digest = legacy_sighash_for_signing(
            &self.unsigned,
            input_index,
            &prevout.output.script_pubkey,
            sighash_type,
        )?;
        Ok(P2pkhSignRequest {
            unsigned_bytes: self.unsigned.encode(),
            prevouts: prevouts.into(),
            input_index,
            public_key: public_key.into(),
            sighash_type,
            digest,
            budget,
        })
    }

    /// Validate an external result before changing any byte. DER excludes the
    /// mode byte; the PSBT layer appends that byte exactly once after checking.
    pub fn insert_verified_signature(
        &mut self,
        request: &P2pkhSignRequest,
        public_key: &[u8],
        der: &[u8],
        sighash_type: SighashType,
    ) -> Result<(), Error> {
        if self.unsigned.encode() != request.unsigned_bytes {
            return Err(Error::StaleRequest);
        }
        if public_key != request.public_key {
            return Err(Error::WrongPublicKey);
        }
        if sighash_type != request.sighash_type {
            return Err(Error::SighashMismatch);
        }
        let current = self.sign_request(
            request.input_index,
            &request.prevouts,
            public_key,
            sighash_type,
            request.budget,
        )?;
        if current.digest != request.digest {
            return Err(Error::StaleRequest);
        }
        verify_low_s(public_key, der, request.digest)?;
        let mut key = vec![2];
        key.extend_from_slice(public_key);
        let mut signature = der.to_vec();
        signature.push(sighash_type.to_u8());
        self.inputs[request.input_index].insert(key, signature)
    }

    /// Explicit atomic finalization. Unsupported templates are forwarded by the
    /// codec but are never automatically signed, finalized or extracted.
    pub fn finalize_p2pkh(
        &mut self,
        prevouts: &[Prevout],
        budget: PaymentBudget,
    ) -> Result<SignedPayment, Error> {
        self.check_prevouts(prevouts)?;
        let mut finalized = self.clone();
        let mut transaction = self.unsigned.clone();
        for (index, prevout) in prevouts.iter().enumerate() {
            let map = &self.inputs[index];
            let script = if let Some(script) = map.get(&[7]) {
                verify_final(self, index, prevout, script)?;
                script.to_vec()
            } else {
                let mut selected = None;
                for entry in &map.entries {
                    if entry.key.first() != Some(&2) {
                        continue;
                    }
                    let public_key = &entry.key[1..];
                    self.check_template(index, prevout, public_key)?;
                    let (&mode, der) = entry.value.split_last().ok_or(Error::InvalidSignature)?;
                    let mode = SighashType::from_u32(mode.into())?;
                    check_mode(map, mode)?;
                    let digest = legacy_sighash_for_signing(
                        &self.unsigned,
                        index,
                        &prevout.output.script_pubkey,
                        mode,
                    )?;
                    verify_low_s(public_key, der, digest)?;
                    if selected.is_some() {
                        return Err(Error::Conflict);
                    }
                    let mut script = Vec::new();
                    push_data(&mut script, &entry.value).map_err(|_| Error::InvalidFinalScript)?;
                    push_data(&mut script, public_key).map_err(|_| Error::InvalidFinalScript)?;
                    selected = Some(script);
                }
                selected.ok_or(Error::MissingSignature)?
            };
            transaction.inputs[index].script_sig = script.clone();
            let map = &mut finalized.inputs[index];
            // BIP174 removes construction fields after finalizing. UTXOs,
            // unknown and proprietary records retain their bytes and order.
            map.entries
                .retain(|entry| !matches!(entry.key.first(), Some(2..=6)));
            map.insert(vec![7], script)?;
        }
        let summary = budget.check(&transaction, prevouts, transaction.encode().len())?;
        *self = finalized;
        Ok(SignedPayment {
            transaction,
            summary,
        })
    }

    /// Extraction revalidates existing final scriptSigs and the actual signed
    /// size. Merely decoding a final-script field never authorizes extraction.
    pub fn extract(
        &self,
        prevouts: &[Prevout],
        budget: PaymentBudget,
    ) -> Result<SignedPayment, Error> {
        self.check_prevouts(prevouts)?;
        let mut transaction = self.unsigned.clone();
        for (index, prevout) in prevouts.iter().enumerate() {
            let script = self.inputs[index]
                .get(&[7])
                .ok_or(Error::MissingSignature)?;
            verify_final(self, index, prevout, script)?;
            transaction.inputs[index].script_sig = script.into();
        }
        let summary = budget.check(&transaction, prevouts, transaction.encode().len())?;
        Ok(SignedPayment {
            transaction,
            summary,
        })
    }
}

fn decode_txout(bytes: &[u8]) -> Result<TxOut, Error> {
    let mut reader = Reader { bytes, position: 0 };
    let value = u64::from_le_bytes(
        reader
            .take(8)?
            .try_into()
            .map_err(|_| Error::InvalidValue)?,
    );
    let len = reader.count(bytes.len())?;
    let script_pubkey = reader.take(len)?.into();
    if reader.position != bytes.len() {
        return Err(Error::InvalidValue);
    }
    Ok(TxOut {
        value,
        script_pubkey,
    })
}

fn check_mode(map: &RawMap, mode: SighashType) -> Result<(), Error> {
    if let Some(declared) = map.get(&[3])
        && declared != mode.to_u32().to_le_bytes()
    {
        return Err(Error::SighashMismatch);
    }
    Ok(())
}

fn verify_low_s(public_key: &[u8], der: &[u8], digest: Sighash) -> Result<(), Error> {
    let key = valid_public_key(public_key)?;
    let signature = Signature::from_der(der).map_err(|_| Error::InvalidSignature)?;
    if signature.to_der().as_bytes() != der {
        return Err(Error::InvalidSignature);
    }
    if signature.normalize_s().is_some() {
        return Err(Error::HighS);
    }
    key.verify_prehash(digest.as_ref(), &signature)
        .map_err(|_| Error::InvalidSignature)
}

fn verify_final(
    psbt: &PsbtV0,
    index: usize,
    prevout: &Prevout,
    script: &[u8],
) -> Result<(), Error> {
    // Current P2PKH finalization accepts exactly two direct minimal pushes.
    let sig_len = usize::from(*script.first().ok_or(Error::InvalidFinalScript)?);
    if !(9..=73).contains(&sig_len) {
        return Err(Error::InvalidFinalScript);
    }
    let sig_end = 1 + sig_len;
    let signature = script.get(1..sig_end).ok_or(Error::InvalidFinalScript)?;
    let key_len = usize::from(*script.get(sig_end).ok_or(Error::InvalidFinalScript)?);
    let key = script.get(sig_end + 1..).ok_or(Error::InvalidFinalScript)?;
    if !matches!(key_len, 33 | 65) || key.len() != key_len {
        return Err(Error::InvalidFinalScript);
    }
    psbt.check_template(index, prevout, key)?;
    let (&mode, der) = signature.split_last().ok_or(Error::InvalidSignature)?;
    let mode = SighashType::from_u32(mode.into())?;
    check_mode(&psbt.inputs[index], mode)?;
    let digest =
        legacy_sighash_for_signing(&psbt.unsigned, index, &prevout.output.script_pubkey, mode)?;
    verify_low_s(key, der, digest)
}
