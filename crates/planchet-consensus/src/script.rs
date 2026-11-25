//! Borrowed Script instructions and exact templates, without an interpreter.
//!
//! Decoding preserves non-minimal pushes. Template matching is byte-exact;
//! neither decoding nor matching establishes consensus validity or spendability.
use core::{fmt, iter::FusedIterator};
use planchet_primitives::Hash160;

pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_1: u8 = 0x51;
pub const OP_16: u8 = 0x60;
pub const OP_RETURN: u8 = 0x6a;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_CODESEPARATOR: u8 = 0xab;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;

/// An instruction borrowed from the original bytes. Numeric opcodes remain `Op`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Instruction<'a> {
    Op(u8),
    Push {
        opcode: u8,
        data: &'a [u8],
        /// Includes the original opcode and length prefix, even if non-minimal.
        encoded: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptError {
    /// Byte offset of the truncated push's opcode.
    pub offset: usize,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "truncated script push at byte {}", self.offset)
    }
}
impl core::error::Error for ScriptError {}

/// Allocation-free cursor. A malformed push returns one error then terminates.
#[derive(Clone, Debug)]
pub struct Instructions<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Instructions<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub const fn position(&self) -> usize {
        self.offset
    }

    fn decode(&self) -> Option<(Instruction<'a>, usize)> {
        let start = self.offset;
        let opcode = *self.bytes.get(start)?;
        let rest = &self.bytes[start + 1..];
        let (prefix, len) = match opcode {
            0..=75 => (0, u32::from(opcode)),
            OP_PUSHDATA1 => (1, u32::from(*rest.first()?)),
            OP_PUSHDATA2 => (
                2,
                u32::from(u16::from_le_bytes(rest.get(..2)?.try_into().ok()?)),
            ),
            OP_PUSHDATA4 => (4, u32::from_le_bytes(rest.get(..4)?.try_into().ok()?)),
            _ => return Some((Instruction::Op(opcode), start + 1)),
        };
        let len = usize::try_from(len).ok()?;
        let data = rest.get(prefix..)?.get(..len)?;
        let end = (start + 1).checked_add(prefix)?.checked_add(len)?;
        Some((
            Instruction::Push {
                opcode,
                data,
                encoded: &self.bytes[start..end],
            },
            end,
        ))
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Result<Instruction<'a>, ScriptError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        match self.decode() {
            Some((instruction, end)) => {
                self.offset = end;
                Some(Ok(instruction))
            }
            None => {
                let offset = self.offset;
                self.offset = self.bytes.len();
                Some(Err(ScriptError { offset }))
            }
        }
    }
}
impl FusedIterator for Instructions<'_> {}

/// Recognize only `DUP HASH160 PUSH20 <hash> EQUALVERIFY CHECKSIG`.
pub fn match_p2pkh(script: &[u8]) -> Option<Hash160> {
    if script.len() != 25
        || script[..3] != [OP_DUP, OP_HASH160, 20]
        || script[23..] != [OP_EQUALVERIFY, OP_CHECKSIG]
    {
        return None;
    }
    Some(Hash160::from_wire_bytes(script[3..23].try_into().ok()?))
}

pub fn p2pkh_script(hash: Hash160) -> [u8; 25] {
    let mut script = [0; 25];
    script[..3].copy_from_slice(&[OP_DUP, OP_HASH160, 20]);
    script[3..23].copy_from_slice(hash.as_wire_bytes());
    script[23..].copy_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    script
}

/// Recognize only `HASH160 PUSH20 <hash> EQUAL`.
pub fn match_p2sh(script: &[u8]) -> Option<Hash160> {
    if script.len() != 23 || script[..2] != [OP_HASH160, 20] || script[22] != OP_EQUAL {
        return None;
    }
    Some(Hash160::from_wire_bytes(script[2..22].try_into().ok()?))
}

pub fn p2sh_script(hash: Hash160) -> [u8; 23] {
    let mut script = [0; 23];
    script[..2].copy_from_slice(&[OP_HASH160, 20]);
    script[2..22].copy_from_slice(hash.as_wire_bytes());
    script[22] = OP_EQUAL;
    script
}

/// Tests the leading opcode only; no claim about relay policy or payload shape.
pub fn is_op_return(script: &[u8]) -> bool {
    script.first() == Some(&OP_RETURN)
}

/// Exact `OP_m <pubkeys...> OP_n CHECKMULTISIG`, limited to 1 <= m <= n <= 16.
/// Keys have compressed/uncompressed SEC encoding shape; curve validity and
/// relay policy are separate checks. Key order is preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultisigRef<'a> {
    pub required: u8,
    pub key_count: u8,
    keys: &'a [u8],
}

impl<'a> MultisigRef<'a> {
    pub fn pubkeys(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        Instructions::new(self.keys).map(|instruction| match instruction {
            Ok(Instruction::Push { data, .. }) => data,
            _ => unreachable!("validated multisig key push"),
        })
    }
}

fn small_positive(opcode: u8) -> Option<u8> {
    (OP_1..=OP_16).contains(&opcode).then(|| opcode - OP_1 + 1)
}

fn pubkey_shape(key: &[u8]) -> bool {
    matches!((key.len(), key.first()), (33, Some(2 | 3)) | (65, Some(4)))
}

pub fn match_multisig(script: &[u8]) -> Option<MultisigRef<'_>> {
    let required = small_positive(*script.first()?)?;
    let mut cursor = Instructions::new(&script[1..]);
    let mut key_count = 0u8;
    loop {
        let start = cursor.position();
        match cursor.next()?.ok()? {
            Instruction::Push { opcode, data, .. }
                if matches!(opcode, 33 | 65) && pubkey_shape(data) =>
            {
                key_count = key_count.checked_add(1)?;
                if key_count > 16 {
                    return None;
                }
            }
            Instruction::Op(opcode) if small_positive(opcode) == Some(key_count) => {
                if required > key_count
                    || cursor.next()? != Ok(Instruction::Op(OP_CHECKMULTISIG))
                    || cursor.next().is_some()
                {
                    return None;
                }
                return Some(MultisigRef {
                    required,
                    key_count,
                    keys: &script[1..1 + start],
                });
            }
            _ => return None,
        }
    }
}

/// A minimally encoded nonnegative u32 locktime followed by `CLTV DROP` and
/// a borrowed suffix. No execution, sequence/version, or locktime check occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CltvRef<'a> {
    pub lock_time: u32,
    pub inner_script: &'a [u8],
}

pub fn match_cltv(script: &[u8]) -> Option<CltvRef<'_>> {
    let mut cursor = Instructions::new(script);
    let lock_time = match cursor.next()?.ok()? {
        Instruction::Op(opcode) => u32::from(small_positive(opcode)?),
        Instruction::Push {
            opcode: OP_0,
            data: [],
            ..
        } => 0,
        Instruction::Push { opcode, data, .. } => {
            if data.is_empty() || data.len() > 5 || opcode as usize != data.len() {
                return None;
            }
            // ScriptNum's sign bit and redundant sign-byte rules, plus the
            // minimal push rule requiring OP_1..OP_16 for those integers.
            let last = *data.last()?;
            if last & 0x80 != 0
                || (last & 0x7f == 0 && (data.len() <= 1 || data[data.len() - 2] & 0x80 == 0))
                || (data.len() == 1 && (1..=16).contains(&data[0]))
            {
                return None;
            }
            let mut value = 0u64;
            for (i, byte) in data.iter().enumerate() {
                value |= u64::from(*byte) << (8 * i);
            }
            u32::try_from(value).ok()?
        }
    };
    if cursor.next()? != Ok(Instruction::Op(OP_CHECKLOCKTIMEVERIFY))
        || cursor.next()? != Ok(Instruction::Op(OP_DROP))
    {
        return None;
    }
    Some(CltvRef {
        lock_time,
        inner_script: &script[cursor.position()..],
    })
}

#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultisigError {
    InvalidThreshold,
    InvalidPubkeyEncoding,
}

#[cfg(feature = "alloc")]
impl fmt::Display for MultisigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidThreshold => "multisig requires 1 <= m <= n <= 16",
            Self::InvalidPubkeyEncoding => {
                "multisig key must have compressed/uncompressed SEC encoding shape"
            }
        })
    }
}
#[cfg(feature = "alloc")]
impl core::error::Error for MultisigError {}

/// Build the narrow template recognized by `match_multisig`, preserving keys
/// in caller order. This does not parse curve points or establish relay policy.
#[cfg(feature = "alloc")]
pub fn multisig_script(required: u8, keys: &[&[u8]]) -> Result<alloc::vec::Vec<u8>, MultisigError> {
    if required == 0 || keys.is_empty() || keys.len() > 16 || usize::from(required) > keys.len() {
        return Err(MultisigError::InvalidThreshold);
    }
    if keys.iter().any(|key| !pubkey_shape(key)) {
        return Err(MultisigError::InvalidPubkeyEncoding);
    }
    let mut script = alloc::vec![OP_1 + required - 1];
    for key in keys {
        script.push(key.len() as u8);
        script.extend_from_slice(key);
    }
    script.extend_from_slice(&[OP_1 + keys.len() as u8 - 1, OP_CHECKMULTISIG]);
    Ok(script)
}

/// Prefix an arbitrary inner script with a minimal u32 ScriptNum and CLTV DROP.
#[cfg(feature = "alloc")]
pub fn cltv_script(lock_time: u32, inner_script: &[u8]) -> alloc::vec::Vec<u8> {
    let mut script = alloc::vec::Vec::new();
    let mut data = [0; 5];
    let mut value = lock_time;
    let mut len = 0;
    while value != 0 {
        data[len] = value as u8;
        value >>= 8;
        len += 1;
    }
    if len != 0 && data[len - 1] & 0x80 != 0 {
        len += 1;
    }
    push_data(&mut script, &data[..len]).expect("u32 ScriptNum fits a push");
    script.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP]);
    script.extend_from_slice(inner_script);
    script
}

#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PushTooLarge;

#[cfg(feature = "alloc")]
impl fmt::Display for PushTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("script push length exceeds u32::MAX")
    }
}
#[cfg(feature = "alloc")]
impl core::error::Error for PushTooLarge {}

/// Append the minimal push encoding, including numeric opcodes for 1..16/-1.
///
/// This is an encoding helper, not a script-size/520-byte policy check. It does
/// not rewrite an existing script. On length overflow `script` is unchanged.
#[cfg(feature = "alloc")]
pub fn push_data(script: &mut alloc::vec::Vec<u8>, data: &[u8]) -> Result<(), PushTooLarge> {
    let len = u32::try_from(data.len()).map_err(|_| PushTooLarge)?;
    match data {
        [] => script.push(OP_0),
        [value @ 1..=16] => script.push(OP_1 + value - 1),
        [0x81] => script.push(OP_1NEGATE),
        _ => {
            match len {
                0..=75 => script.push(len as u8),
                76..=255 => script.extend_from_slice(&[OP_PUSHDATA1, len as u8]),
                256..=65535 => {
                    script.push(OP_PUSHDATA2);
                    script.extend_from_slice(&(len as u16).to_le_bytes());
                }
                _ => {
                    script.push(OP_PUSHDATA4);
                    script.extend_from_slice(&len.to_le_bytes());
                }
            }
            script.extend_from_slice(data);
        }
    }
    Ok(())
}

/// Build `OP_RETURN` followed by a single minimally encoded payload push.
#[cfg(feature = "alloc")]
pub fn op_return_script(data: &[u8]) -> Result<alloc::vec::Vec<u8>, PushTooLarge> {
    let mut script = alloc::vec![OP_RETURN];
    push_data(&mut script, data)?;
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_preserves_nonminimal_pushes_and_opcode_boundaries() {
        // A CODESEPARATOR byte inside a push must remain data for sighash users.
        let bytes = [
            OP_PUSHDATA1,
            1,
            OP_CODESEPARATOR,
            OP_PUSHDATA2,
            0,
            0,
            OP_PUSHDATA4,
            1,
            0,
            0,
            0,
            7,
            OP_1,
            OP_0,
        ];
        let mut cursor = Instructions::new(&bytes);
        assert_eq!(
            cursor.next(),
            Some(Ok(Instruction::Push {
                opcode: OP_PUSHDATA1,
                data: &[OP_CODESEPARATOR],
                encoded: &bytes[..3],
            }))
        );
        assert_eq!(cursor.position(), 3);
        assert_eq!(
            cursor.next(),
            Some(Ok(Instruction::Push {
                opcode: OP_PUSHDATA2,
                data: &[],
                encoded: &bytes[3..6],
            }))
        );
        assert_eq!(
            cursor.next(),
            Some(Ok(Instruction::Push {
                opcode: OP_PUSHDATA4,
                data: &[7],
                encoded: &bytes[6..12],
            }))
        );
        assert_eq!(cursor.next(), Some(Ok(Instruction::Op(OP_1))));
        assert_eq!(
            cursor.next(),
            Some(Ok(Instruction::Push {
                opcode: OP_0,
                data: &[],
                encoded: &[OP_0],
            }))
        );
        assert_eq!(cursor.next(), None);
    }

    #[test]
    fn truncated_pushes_fail_once_without_panicking() {
        for push in [
            &[1][..],
            &[OP_PUSHDATA1][..],
            &[OP_PUSHDATA1, 2, 1][..],
            &[OP_PUSHDATA2, 1][..],
            &[OP_PUSHDATA4, 0xff, 0xff, 0xff, 0xff][..],
        ] {
            let mut cursor = Instructions::new(push);
            assert_eq!(cursor.next(), Some(Err(ScriptError { offset: 0 })));
            assert_eq!(cursor.next(), None);
        }
        let mut cursor = Instructions::new(&[OP_DUP, 2, 1]);
        assert_eq!(cursor.next(), Some(Ok(Instruction::Op(OP_DUP))));
        assert_eq!(cursor.next(), Some(Err(ScriptError { offset: 1 })));
    }

    #[test]
    fn templates_are_exact_not_semantic_matches() {
        let hash = Hash160::from_wire_bytes([0x42; 20]);
        let pkh = [
            0x76, 0xa9, 0x14, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x88, 0xac,
        ];
        assert_eq!(p2pkh_script(hash), pkh);
        assert_eq!(match_p2pkh(&pkh), Some(hash));
        let sh = [
            0xa9, 0x14, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x87,
        ];
        assert_eq!(p2sh_script(hash), sh);
        assert_eq!(match_p2sh(&sh), Some(hash));
        assert_eq!(match_p2pkh(&pkh[..24]), None);
        let mut extra = [0; 26];
        extra[..25].copy_from_slice(&pkh);
        assert_eq!(match_p2pkh(&extra), None);
        let mut nonminimal = [0x42; 24];
        nonminimal[..3].copy_from_slice(&[OP_HASH160, OP_PUSHDATA1, 20]);
        nonminimal[23] = OP_EQUAL;
        assert_eq!(match_p2sh(&nonminimal), None);
        assert!(is_op_return(&[OP_RETURN, OP_PUSHDATA4]));
        assert!(!is_op_return(&[1, OP_RETURN]));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn minimal_push_encoding_uses_numeric_and_length_boundaries() {
        for (data, expected) in [
            (&[][..], &[0][..]),
            (&[0][..], &[1, 0][..]),
            (&[1][..], &[0x51][..]),
            (&[16][..], &[0x60][..]),
            (&[0x81][..], &[0x4f][..]),
            (&[17][..], &[1, 17][..]),
        ] {
            let mut script = alloc::vec::Vec::new();
            push_data(&mut script, data).unwrap();
            assert_eq!(script, expected);
        }
        // Prefixes are fixed by the Script wire format, independently of decoder.
        for (len, prefix) in [
            (75, &[75][..]),
            (76, &[0x4c, 76][..]),
            (255, &[0x4c, 255][..]),
            (256, &[0x4d, 0, 1][..]),
            (65535, &[0x4d, 255, 255][..]),
            (65536, &[0x4e, 0, 0, 1, 0][..]),
        ] {
            let data = alloc::vec![0x42; len];
            let mut script = alloc::vec::Vec::new();
            push_data(&mut script, &data).unwrap();
            assert_eq!(&script[..prefix.len()], prefix);
            assert_eq!(&script[prefix.len()..], data);
        }
        assert_eq!(op_return_script(b"doge").unwrap(), b"\x6a\x04doge");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn multisig_template_preserves_order_and_rejects_nonminimal_or_invalid_shapes() {
        let mut a = [0x11; 33];
        a[0] = 2;
        let mut b = [0x22; 65];
        b[0] = 4;
        let script = multisig_script(2, &[&a, &b]).unwrap();
        assert_eq!(&script[..2], &[OP_1 + 1, 33]);
        assert_eq!(&script[36..101], &b);
        assert_eq!(&script[101..], &[OP_1 + 1, OP_CHECKMULTISIG]);
        let parsed = match_multisig(&script).unwrap();
        assert_eq!((parsed.required, parsed.key_count), (2, 2));
        assert!(parsed.pubkeys().eq([&a[..], &b[..]]));
        assert_eq!(
            multisig_script(0, &[&a]),
            Err(MultisigError::InvalidThreshold)
        );
        assert_eq!(
            multisig_script(2, &[&a]),
            Err(MultisigError::InvalidThreshold)
        );
        assert_eq!(
            multisig_script(1, &[&[0; 33]]),
            Err(MultisigError::InvalidPubkeyEncoding)
        );
        let mut nonminimal = alloc::vec![OP_1 + 1, OP_PUSHDATA1];
        nonminimal.extend_from_slice(&script[1..]);
        assert_eq!(match_multisig(&nonminimal), None);
        let mut trailing = script;
        trailing.push(OP_0);
        assert_eq!(match_multisig(&trailing), None);
    }

    #[test]
    fn cltv_match_rejects_negative_redundant_nonminimal_and_overflow_numbers() {
        for bytes in [
            &[1, 0x81][..],
            &[1, 0][..],
            &[1, 1][..],
            &[2, 17, 0][..],
            &[OP_PUSHDATA1, 1, 17][..],
            &[5, 0, 0, 0, 0, 1][..],
        ] {
            let mut script = [0; 8];
            script[..bytes.len()].copy_from_slice(bytes);
            script[bytes.len()..bytes.len() + 2]
                .copy_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP]);
            assert_eq!(match_cltv(&script[..bytes.len() + 2]), None);
        }
        assert_eq!(match_cltv(&[1, 128, OP_CHECKLOCKTIMEVERIFY, OP_DROP]), None);
        assert_eq!(match_cltv(&[OP_1, OP_CHECKLOCKTIMEVERIFY]), None);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn cltv_builder_obeys_scriptnum_sign_padding_and_keeps_inner_bytes() {
        for (time, prefix) in [
            (0, &[0][..]),
            (1, &[0x51][..]),
            (16, &[0x60][..]),
            (17, &[1, 17][..]),
            (127, &[1, 127][..]),
            (128, &[2, 128, 0][..]),
            (255, &[2, 255, 0][..]),
            (256, &[2, 0, 1][..]),
            (u32::MAX, &[5, 255, 255, 255, 255, 0][..]),
        ] {
            let inner = [OP_PUSHDATA1, 0, OP_RETURN];
            let script = cltv_script(time, &inner);
            assert_eq!(&script[..prefix.len()], prefix);
            assert_eq!(&script[prefix.len()..prefix.len() + 2], &[0xb1, 0x75]);
            assert_eq!(
                match_cltv(&script),
                Some(CltvRef {
                    lock_time: time,
                    inner_script: &inner
                })
            );
        }
    }
}
