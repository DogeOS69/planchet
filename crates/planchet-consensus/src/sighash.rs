//! Core-compatible legacy SignatureHash. No Script VM is implied by this API.
use crate::transaction::{Transaction, TxOut};
use alloc::vec::Vec;
use core::fmt;
use planchet_primitives::{Sighash, sha256d};

/// Defined legacy modes accepted for new signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SighashType {
    All = 1,
    None = 2,
    Single = 3,
    AllAnyoneCanPay = 0x81,
    NoneAnyoneCanPay = 0x82,
    SingleAnyoneCanPay = 0x83,
}

impl SighashType {
    pub fn from_u32(value: u32) -> Result<Self, SighashError> {
        match value {
            1 => Ok(Self::All),
            2 => Ok(Self::None),
            3 => Ok(Self::Single),
            0x81 => Ok(Self::AllAnyoneCanPay),
            0x82 => Ok(Self::NoneAnyoneCanPay),
            0x83 => Ok(Self::SingleAnyoneCanPay),
            _ => Err(SighashError::UndefinedMode),
        }
    }
    pub const fn to_u32(self) -> u32 {
        self as u32
    }
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    pub const fn anyone_can_pay(self) -> bool {
        self.to_u32() & 0x80 != 0
    }
    pub const fn is_single(self) -> bool {
        self.to_u32() & 0x1f == 3
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SighashError {
    InputIndex,
    SingleWithoutOutput,
    UndefinedMode,
}
impl fmt::Display for SighashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for SighashError {}

/// The historical uint256::ONE result, in digest order (never RPC-reversed).
pub fn historical_one() -> Sighash {
    let mut bytes = [0; 32];
    bytes[0] = 1;
    Sighash::from_wire_bytes(bytes)
}

/// Remove OP_CODESEPARATOR instructions, not bytes inside pushes. As in Core,
/// malformed trailing instructions are retained unchanged after parsing stops.
/// The caller supplies scriptCode after the last *executed* separator and any
/// legacy FindAndDelete(signature) operation required by its Script context.
pub fn remove_code_separators(script: &[u8]) -> Vec<u8> {
    use crate::script::{Instruction, Instructions, OP_CODESEPARATOR};
    let mut result = Vec::with_capacity(script.len());
    let mut instructions = Instructions::new(script);
    loop {
        let start = instructions.position();
        match instructions.next() {
            Some(Ok(Instruction::Op(OP_CODESEPARATOR))) => {}
            Some(Ok(_)) => result.extend_from_slice(&script[start..instructions.position()]),
            Some(Err(_)) => {
                result.extend_from_slice(&script[start..]);
                break;
            }
            None => break,
        }
    }
    result
}

/// Historical verification semantics, including arbitrary 32-bit hash types and
/// SINGLE's missing-output bug. Undefined base modes behave as ALL, as in Core.
/// This computes the digest only; it does not execute scripts or verify ECDSA.
pub fn legacy_sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    hash_type: u32,
) -> Sighash {
    if input_index >= tx.inputs.len() || (hash_type & 0x1f == 3 && input_index >= tx.outputs.len())
    {
        return historical_one();
    }
    let mut signing = tx.clone();
    for input in &mut signing.inputs {
        input.script_sig.clear();
    }
    signing.inputs[input_index].script_sig = remove_code_separators(script_code);
    match hash_type & 0x1f {
        2 => {
            signing.outputs.clear();
        }
        3 => {
            signing.outputs.truncate(input_index + 1);
            for output in &mut signing.outputs[..input_index] {
                *output = TxOut {
                    value: u64::MAX,
                    script_pubkey: Vec::new(),
                };
            }
        }
        _ => {}
    }
    if matches!(hash_type & 0x1f, 2 | 3) {
        for (index, input) in signing.inputs.iter_mut().enumerate() {
            if index != input_index {
                input.sequence = 0;
            }
        }
    }
    if hash_type & 0x80 != 0 {
        let input = signing.inputs.swap_remove(input_index);
        signing.inputs.clear();
        signing.inputs.push(input);
    }
    let mut preimage = signing.encode();
    preimage.extend_from_slice(&hash_type.to_le_bytes());
    Sighash::from_wire_bytes(sha256d(&preimage))
}

/// New signing refuses invalid input indices and SINGLE without an output.
pub fn legacy_sighash_for_signing(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    hash_type: SighashType,
) -> Result<Sighash, SighashError> {
    if input_index >= tx.inputs.len() {
        return Err(SighashError::InputIndex);
    }
    if hash_type.is_single() && input_index >= tx.outputs.len() {
        return Err(SighashError::SingleWithoutOutput);
    }
    Ok(legacy_sighash(
        tx,
        input_index,
        script_code,
        hash_type.to_u32(),
    ))
}

#[cfg(test)]
mod tests {
    use super::remove_code_separators;

    // Protect opcode boundaries, which a byte-filter implementation would lose.
    // Expected literals follow Script's direct/PUSHDATA1/2/4 wire encodings.
    #[test]
    fn separators_in_pushes_and_malformed_suffix_are_preserved() {
        let script = [
            0xab, 1, 0xab, 0x4c, 1, 0xab, 0x4d, 1, 0, 0xab, 0x4e, 1, 0, 0, 0, 0xab, 0xab, 0x51,
        ];
        assert_eq!(
            remove_code_separators(&script),
            [
                1, 0xab, 0x4c, 1, 0xab, 0x4d, 1, 0, 0xab, 0x4e, 1, 0, 0, 0, 0xab, 0x51
            ]
        );
        assert_eq!(
            remove_code_separators(&[0xab, 0x4c, 2, 0xab]),
            [0x4c, 2, 0xab]
        );
    }
}
