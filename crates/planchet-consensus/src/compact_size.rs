//! Canonical CompactSize, with explicit bounds and no allocation.
use crate::DecodeError;

/// Decode a shortest-form CompactSize prefix, rejecting values over `maximum`.
pub fn decode_compact_size(bytes: &[u8], maximum: u64) -> Result<(u64, usize), DecodeError> {
    let tag = *bytes
        .first()
        .ok_or(DecodeError::UnexpectedEof { offset: 0 })?;
    let size = match tag {
        0xfd => 3,
        0xfe => 5,
        0xff => 9,
        _ => 1,
    };
    let raw = bytes
        .get(..size)
        .ok_or(DecodeError::UnexpectedEof { offset: 1 })?;
    let mut value = if size == 1 { u64::from(tag) } else { 0 };
    for (i, byte) in raw[1..].iter().enumerate() {
        value |= u64::from(*byte) << (8 * i);
    }
    if (tag == 0xfd && value < 0xfd)
        || (tag == 0xfe && value <= 0xffff)
        || (tag == 0xff && value <= 0xffff_ffff)
    {
        return Err(DecodeError::NonMinimalCompactSize { offset: 0 });
    }
    if value > maximum {
        return Err(DecodeError::LimitExceeded {
            resource: "CompactSize",
            limit: usize::try_from(maximum).unwrap_or(usize::MAX),
        });
    }
    Ok((value, size))
}

pub const fn compact_size_len(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Write canonical bytes, leaving any suffix of `out` untouched.
pub fn encode_compact_size(value: u64, out: &mut [u8]) -> Result<usize, DecodeError> {
    let size = compact_size_len(value);
    if out.len() < size {
        return Err(DecodeError::BufferTooSmall {
            needed: size,
            available: out.len(),
        });
    }
    if size == 1 {
        out[0] = value as u8;
    } else {
        out[0] = match size {
            3 => 0xfd,
            5 => 0xfe,
            _ => 0xff,
        };
        out[1..size].copy_from_slice(&value.to_le_bytes()[..size - 1]);
    }
    Ok(size)
}
