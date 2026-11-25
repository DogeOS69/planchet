//! Validated legacy transaction views; script ranges are relative to transaction bytes.
use crate::{
    DecodeError, DecodeLimits,
    decode::{Cursor, bound, exact},
};
use core::{iter::FusedIterator, ops::Range};
use planchet_primitives::{Txid, sha256d};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxRef<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) layout: Layout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    pub inputs_start: usize,
    pub inputs_end: usize,
    pub input_count: usize,
    pub outputs_start: usize,
    pub outputs_end: usize,
    pub output_count: usize,
    pub lock_time_start: usize,
}

impl<'a> TxRef<'a> {
    pub fn decode_exact(bytes: &'a [u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        bound(bytes.len(), limits.max_tx_bytes, "transaction bytes")?;
        let (tx, consumed) = Self::decode_prefix(bytes, limits)?;
        exact(consumed, bytes.len())?;
        Ok(tx)
    }
    /// Decode an explicitly legacy/non-witness unsigned transaction (for PSBT).
    /// Unlike native block decoding, permits zero inputs. After an empty vin,
    /// the next byte is an output count, never a witness flag. This method
    /// checks wire structure, not PSBT's separate empty-scriptSig requirement.
    pub fn decode_unsigned_exact(
        bytes: &'a [u8],
        limits: DecodeLimits,
    ) -> Result<Self, DecodeError> {
        bound(bytes.len(), limits.max_tx_bytes, "transaction bytes")?;
        let (tx, consumed) = Self::decode_legacy_prefix(bytes, limits, true)?;
        exact(consumed, bytes.len())?;
        Ok(tx)
    }
    pub fn decode_prefix(
        bytes: &'a [u8],
        limits: DecodeLimits,
    ) -> Result<(Self, usize), DecodeError> {
        Self::decode_legacy_prefix(bytes, limits, false)
    }
    fn decode_legacy_prefix(
        bytes: &'a [u8],
        limits: DecodeLimits,
        allow_empty_inputs: bool,
    ) -> Result<(Self, usize), DecodeError> {
        let mut c = Cursor::new(bytes, limits.max_tx_bytes, "transaction bytes");
        c.take(4)?;
        let count = c.count(limits.max_inputs, "transaction inputs")?;
        if count == 0 && !allow_empty_inputs {
            return Err(if bytes.get(c.pos) == Some(&1) {
                DecodeError::WitnessNotAllowed
            } else {
                DecodeError::MissingInputs
            });
        }
        let mut layout = scan_body(&mut c, count, limits)?;
        layout.lock_time_start = c.pos;
        c.take(4)?;
        Ok((
            Self {
                bytes: &bytes[..c.pos],
                layout,
            },
            c.pos,
        ))
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn version(&self) -> i32 {
        self.version_bits() as i32
    }
    pub fn version_bits(&self) -> u32 {
        u32::from_le_bytes(self.bytes[..4].try_into().expect("validated version"))
    }
    pub fn lock_time(&self) -> u32 {
        u32::from_le_bytes(
            self.bytes[self.layout.lock_time_start..][..4]
                .try_into()
                .expect("validated locktime"),
        )
    }
    pub fn input_count(&self) -> usize {
        self.layout.input_count
    }
    pub fn output_count(&self) -> usize {
        self.layout.output_count
    }
    pub fn inputs(&self) -> Inputs<'a> {
        inputs(self.bytes, self.layout)
    }
    pub fn outputs(&self) -> Outputs<'a> {
        outputs(self.bytes, self.layout)
    }
    /// Hash the complete signed legacy wire bytes, preserving every script byte.
    pub fn txid(&self) -> Txid {
        Txid::from_wire_bytes(sha256d(self.bytes))
    }
    pub fn is_coinbase(&self) -> bool {
        self.input_count() == 1
            && self
                .inputs()
                .next()
                .is_some_and(|input| input.is_coinbase())
    }
}

pub(crate) fn scan_body(
    c: &mut Cursor<'_>,
    input_count: usize,
    limits: DecodeLimits,
) -> Result<Layout, DecodeError> {
    c.possible(input_count, 41)?;
    let inputs_start = c.pos;
    for _ in 0..input_count {
        c.take(36)?;
        let len = c.count(limits.max_script_bytes, "input script bytes")?;
        c.take(len)?;
        c.take(4)?;
    }
    let inputs_end = c.pos;
    let output_count = c.count(limits.max_outputs, "transaction outputs")?;
    c.possible(output_count, 9)?;
    let outputs_start = c.pos;
    for _ in 0..output_count {
        c.take(8)?;
        let len = c.count(limits.max_script_bytes, "output script bytes")?;
        c.take(len)?;
    }
    Ok(Layout {
        inputs_start,
        inputs_end,
        input_count,
        outputs_start,
        outputs_end: c.pos,
        output_count,
        lock_time_start: c.pos,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInRef<'a> {
    bytes: &'a [u8],
    script: &'a [u8],
    script_range: Range<usize>,
}
impl<'a> TxInRef<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn previous_txid(&self) -> Txid {
        Txid::from_wire_bytes(self.bytes[..32].try_into().expect("validated outpoint"))
    }
    pub fn vout(&self) -> u32 {
        u32::from_le_bytes(self.bytes[32..36].try_into().expect("validated vout"))
    }
    pub fn sequence(&self) -> u32 {
        u32::from_le_bytes(
            self.bytes[self.bytes.len() - 4..]
                .try_into()
                .expect("validated sequence"),
        )
    }
    pub fn script_sig(&self) -> &'a [u8] {
        self.script
    }
    pub fn script_sig_range(&self) -> Range<usize> {
        self.script_range.clone()
    }
    pub fn is_coinbase(&self) -> bool {
        self.bytes[..32] == [0; 32] && self.vout() == u32::MAX
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutRef<'a> {
    bytes: &'a [u8],
    script: &'a [u8],
    script_range: Range<usize>,
}
impl<'a> TxOutRef<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Raw output value bits. Decoding does not enforce nonnegative/MAX_MONEY.
    pub fn value(&self) -> u64 {
        u64::from_le_bytes(self.value_wire_bytes())
    }
    pub fn value_wire_bytes(&self) -> [u8; 8] {
        self.bytes[..8].try_into().expect("validated value")
    }
    pub fn script_pubkey(&self) -> &'a [u8] {
        self.script
    }
    pub fn script_pubkey_range(&self) -> Range<usize> {
        self.script_range.clone()
    }
}

#[derive(Clone, Debug)]
pub struct Inputs<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}
pub(crate) fn inputs(bytes: &[u8], layout: Layout) -> Inputs<'_> {
    let mut cursor = Cursor::new(bytes, layout.inputs_end, "validated inputs");
    cursor.pos = layout.inputs_start;
    Inputs {
        cursor,
        remaining: layout.input_count,
    }
}
impl<'a> Iterator for Inputs<'a> {
    type Item = TxInRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let c = &mut self.cursor;
        let start = c.pos;
        c.take(36).expect("validated input");
        let len = c
            .count(usize::MAX, "validated script")
            .expect("validated script length");
        let script_start = c.pos;
        let script = c.take(len).expect("validated script");
        let script_range = script_start..c.pos;
        c.take(4).expect("validated sequence");
        self.remaining -= 1;
        Some(TxInRef {
            bytes: &c.bytes[start..c.pos],
            script,
            script_range,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Inputs<'_> {}
impl FusedIterator for Inputs<'_> {}

#[derive(Clone, Debug)]
pub struct Outputs<'a> {
    cursor: Cursor<'a>,
    remaining: usize,
}
pub(crate) fn outputs(bytes: &[u8], layout: Layout) -> Outputs<'_> {
    let mut cursor = Cursor::new(bytes, layout.outputs_end, "validated outputs");
    cursor.pos = layout.outputs_start;
    Outputs {
        cursor,
        remaining: layout.output_count,
    }
}
impl<'a> Iterator for Outputs<'a> {
    type Item = TxOutRef<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let c = &mut self.cursor;
        let start = c.pos;
        c.take(8).expect("validated output");
        let len = c
            .count(usize::MAX, "validated script")
            .expect("validated script length");
        let script_start = c.pos;
        let script = c.take(len).expect("validated script");
        let script_range = script_start..c.pos;
        self.remaining -= 1;
        Some(TxOutRef {
            bytes: &c.bytes[start..c.pos],
            script,
            script_range,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Outputs<'_> {}
impl FusedIterator for Outputs<'_> {}
