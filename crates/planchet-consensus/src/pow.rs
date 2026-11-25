//! Compact target validation and optional pure Rust scrypt work hashing.
//!
//! A Dogecoin block ID is SHA256d of its base header; the work digest is
//! scrypt(1024, 1, 1, 32), with the same 80 bytes as password and salt.
//! This module does not validate difficulty transitions, AuxPoW, chain links,
//! activation rules, cumulative work, or selection of a best chain.
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    Zero,
    Negative,
    Overflow,
    AboveLimit,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Zero => "compact target is zero",
            Self::Negative => "compact target is negative",
            Self::Overflow => "compact target exceeds 256 bits",
            Self::AboveLimit => "compact target exceeds supplied proof-of-work limit",
        })
    }
}
impl core::error::Error for TargetError {}

/// A nonzero, nonnegative, at-most-256-bit decoded compact target.
///
/// Private bytes prevent bypassing validation. This does not certify that a
/// header's bits are the expected difficulty for its network or height.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactTarget([u8; 32]);

impl CompactTarget {
    /// Decode Core's compact format (including its truncation for exponents
    /// below three). Noncanonical encodings of valid values are accepted as in
    /// Core's SetCompact; no network/height difficulty rule is applied.
    pub fn from_compact(bits: u32) -> Result<Self, TargetError> {
        let size = bits >> 24;
        let mut word = bits & 0x007f_ffff;
        if size <= 3 {
            word >>= 8 * (3 - size);
        }
        if word == 0 {
            return Err(TargetError::Zero);
        }
        if bits & 0x0080_0000 != 0 {
            return Err(TargetError::Negative);
        }
        if size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32) {
            return Err(TargetError::Overflow);
        }
        let mut bytes = [0; 32];
        if size <= 3 {
            bytes[..4].copy_from_slice(&word.to_le_bytes());
        } else {
            let offset = (size - 3) as usize;
            for (i, byte) in word.to_le_bytes()[..3].iter().enumerate() {
                if offset + i < bytes.len() {
                    bytes[offset + i] = *byte;
                }
            }
        }
        Ok(Self(bytes))
    }

    /// Also enforce a caller-selected, validated network PoW limit.
    pub fn from_compact_with_limit(bits: u32, limit: Self) -> Result<Self, TargetError> {
        let target = Self::from_compact(bits)?;
        if !leq_le(&target.0, &limit.0) {
            return Err(TargetError::AboveLimit);
        }
        Ok(target)
    }

    /// The numeric target, least-significant byte first.
    pub const fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }
}

fn leq_le(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter().rev().cmp(right.iter().rev()).is_le()
}

/// Raw scrypt work digest, deliberately distinct from `BlockHash` (SHA256d).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePowHash([u8; 32]);

impl NativePowHash {
    /// Import a digest computed by another backend. This only tags bytes; it
    /// does not prove how they were computed or validate a header.
    pub const fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_raw_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Numeric little-endian comparison, with equality accepted. The target
    /// must have passed compact validation; no raw bits comparison is exposed.
    pub fn meets_target(self, target: CompactTarget) -> bool {
        leq_le(&self.0, &target.0)
    }
}

/// Compute scrypt(N=1024, r=1, p=1, output=32) on exactly 80 base-header bytes.
///
/// Requires an allocator (~128 KiB working memory) and no entropy or native
/// crypto library. This computes the function even for AuxPoW-flagged headers;
/// it does not establish that the child header is where work must be checked.
#[cfg(feature = "pow-scrypt")]
pub fn native_pow_hash(header: &[u8; 80]) -> NativePowHash {
    let params =
        scrypt::Params::new(10, 1, 1, 32).expect("fixed Dogecoin scrypt parameters are valid");
    let mut digest = [0; 32];
    scrypt::scrypt(header, header, &params, &mut digest)
        .expect("fixed 32-byte scrypt output is valid");
    NativePowHash(digest)
}

#[cfg(feature = "pow-scrypt")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePowError {
    AuxPowHeader,
    Target(TargetError),
    InsufficientWork,
}

#[cfg(feature = "pow-scrypt")]
impl fmt::Display for NativePowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuxPowHeader => {
                f.write_str("native proof-of-work check does not support AuxPoW headers")
            }
            Self::Target(error) => error.fmt(f),
            Self::InsufficientWork => f.write_str("scrypt digest exceeds target"),
        }
    }
}
#[cfg(feature = "pow-scrypt")]
impl core::error::Error for NativePowError {}

/// Check a non-AuxPoW header against its decoded bits and supplied PoW limit.
///
/// The caller still must establish the required bits at this network/height
/// and whether native mining is permitted. Success is not chain validation.
#[cfg(feature = "pow-scrypt")]
pub fn check_native_pow(
    header: &[u8; 80],
    pow_limit: CompactTarget,
) -> Result<NativePowHash, NativePowError> {
    let version = u32::from_le_bytes(header[..4].try_into().expect("fixed header length"));
    if version & (1 << 8) != 0 {
        return Err(NativePowError::AuxPowHeader);
    }
    let bits = u32::from_le_bytes(header[72..76].try_into().expect("fixed header length"));
    let target =
        CompactTarget::from_compact_with_limit(bits, pow_limit).map_err(NativePowError::Target)?;
    let hash = native_pow_hash(header);
    if !hash.meets_target(target) {
        return Err(NativePowError::InsufficientWork);
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_rejects_sign_zero_and_256_bit_overflow() {
        for bits in [0, 0x0100_3456, 0x0200_0080, 0x0080_0001, 0x2300_0000] {
            assert_eq!(CompactTarget::from_compact(bits), Err(TargetError::Zero));
        }
        assert_eq!(
            CompactTarget::from_compact(0x1d80_ffff),
            Err(TargetError::Negative)
        );
        for bits in [0x2300_0001, 0x2200_0100, 0x2101_0000] {
            assert_eq!(
                CompactTarget::from_compact(bits),
                Err(TargetError::Overflow)
            );
        }
        for bits in [0x2200_00ff, 0x2100_ffff, 0x207f_ffff] {
            assert!(CompactTarget::from_compact(bits).is_ok());
        }
        // Core SetCompact right-shifts a short mantissa, and tolerates unused
        // low bytes: both encodings represent the integer 0x12.
        let mut eighteen = [0; 32];
        eighteen[0] = 0x12;
        assert_eq!(
            CompactTarget::from_compact(0x0112_3456)
                .unwrap()
                .to_le_bytes(),
            eighteen
        );
        assert_eq!(
            CompactTarget::from_compact(0x0112_0000)
                .unwrap()
                .to_le_bytes(),
            eighteen
        );
        let mut target = [0; 32];
        target[26..28].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(
            CompactTarget::from_compact(0x1d00_ffff)
                .unwrap()
                .to_le_bytes(),
            target
        );
    }

    #[test]
    fn target_comparison_is_little_endian_inclusive_and_limit_checked() {
        let target = CompactTarget::from_compact(0x0301_0000).unwrap(); // 65536
        let mut below = [0; 32];
        below[..2].copy_from_slice(&[255, 255]);
        assert!(NativePowHash::from_raw_bytes(below).meets_target(target));
        assert!(NativePowHash::from_raw_bytes(target.to_le_bytes()).meets_target(target));
        let mut above = target.to_le_bytes();
        above[0] = 1;
        assert!(!NativePowHash::from_raw_bytes(above).meets_target(target));
        assert_eq!(
            CompactTarget::from_compact_with_limit(0x0301_0001, target),
            Err(TargetError::AboveLimit)
        );
        assert_eq!(
            CompactTarget::from_compact_with_limit(0x0301_0000, target),
            Ok(target)
        );
    }

    #[cfg(feature = "pow-scrypt")]
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut bytes = [0; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
        }
        bytes
    }

    #[cfg(feature = "pow-scrypt")]
    #[test]
    fn core_regtest_genesis_and_native_105_work_differ_from_block_ids() {
        // Dogecoin Core 1.14.9 regtest heights 0 and 105, recorded 2026-11-24.
        // Expected base-header bytes, RPC-order block IDs and raw scrypt
        // digests follow. Digests cross-checked with Python hashlib (not a
        // Cargo/dev dependency); Core accepted both blocks.
        let vectors = [
            (
                "010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5bdae5494dffff7f2002000000",
                "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5",
                "6a68a6d1d50b88dadbdecdf20e34c66ed8ce8bada7845173a5a8c314ae7a7b66",
            ),
            (
                "040062005be34fc49c86aba9fdc638cb1cd2d603ce0dea4296ca100815ec5752544d68d9f3fe93f720f16cf96be542404ffd491fc81c889fac98369ca8b26b02ecc34706fd70066bffff7f2000000000",
                "76189b4a0ef2e424c6a45972da5636733c60972e52f21944948d0332cfda707c",
                "404be26b6288d88845e54b1d75951026c0f107021e3180f9994b44c0c7c2997a",
            ),
        ];
        let limit = CompactTarget::from_compact(0x207f_ffff).unwrap();
        for (header, id, work) in vectors {
            let header = hex::<80>(header);
            let digest = native_pow_hash(&header);
            assert_eq!(digest.to_raw_bytes(), hex::<32>(work));
            let block_id = planchet_primitives::BlockHash::from_wire_bytes(
                planchet_primitives::sha256d(&header),
            );
            assert_eq!(
                block_id,
                planchet_primitives::BlockHash::from_rpc_hex(id).unwrap()
            );
            assert_ne!(digest.to_raw_bytes(), block_id.to_wire_bytes());
            assert_eq!(check_native_pow(&header, limit), Ok(digest));
            assert_eq!(
                check_native_pow(&header, CompactTarget::from_compact(0x1e0f_fff0).unwrap()),
                Err(NativePowError::Target(TargetError::AboveLimit))
            );
        }
    }

    #[cfg(feature = "pow-scrypt")]
    #[test]
    fn auxpow_106_cannot_pass_native_check_even_when_child_digest_meets_bits() {
        // Dogecoin Core 1.14.9 regtest height 106, block ID
        // 76c8c746788452725dec232c8897bf56f0dab9e50c5cfe97ef105134b4a5a666.
        // Expected child header and raw scrypt digest are embedded below;
        // computing this digest does not verify the actual AuxPoW work.
        let header = hex::<80>(
            "040162007c70dacf32038d944419f2522e97603c733656da7259a4c624e4f20e4a9b1876900b8f672ce044fe8db2377189fc5a5d145769deb0fc942721af550b360af68cfd70066bffff7f2000000000",
        );
        let target = CompactTarget::from_compact(0x207f_ffff).unwrap();
        let digest = native_pow_hash(&header);
        assert_eq!(
            digest.to_raw_bytes(),
            hex::<32>("747efb67085adb5ff5304a8b7e319fb2243763ca435a047d1037c200fa278929")
        );
        assert!(digest.meets_target(target));
        assert_eq!(
            check_native_pow(&header, target),
            Err(NativePowError::AuxPowHeader)
        );
    }

    #[cfg(feature = "pow-scrypt")]
    #[test]
    fn core_mainnet_and_testnet_genesis_scrypt_vectors_and_failed_work() {
        // Dogecoin Core 1.14.9 mainnet/testnet height 0 base headers, recorded
        // 2026-11-24; raw scrypt digests cross-checked with Python hashlib.
        // Block IDs (RPC order), respectively:
        // 1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691
        // bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e
        let vectors = [
            (
                "010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5b24a6a152f0ff0f1e67860100",
                "48b41053487d4159cfaacf3adad783cf2f2dedea1413250cca74783f6f020000",
            ),
            (
                "010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5bb9a7f052f0ff0f1ef7390f00",
                "a74e57fdfb3485b78131157920124e30291c0175e799f6ba5af3585df8060000",
            ),
        ];
        let limit = CompactTarget::from_compact(0x1e0f_fff0).unwrap();
        for (header, work) in vectors {
            let header = hex::<80>(header);
            let digest = native_pow_hash(&header);
            assert_eq!(digest.to_raw_bytes(), hex::<32>(work));
            assert_eq!(check_native_pow(&header, limit), Ok(digest));
        }
        // Regtest genesis with nonce 0 instead of 2: the independent scrypt
        // digest ends in c8 (numeric high byte), above regtest's 7f ceiling.
        let header = hex::<80>(
            "010000000000000000000000000000000000000000000000000000000000000000000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5bdae5494dffff7f2000000000",
        );
        assert_eq!(
            native_pow_hash(&header).to_raw_bytes(),
            hex::<32>("52bda027337ad4581015df66b504a25a43a470693d9ee637181043ea145a48c8")
        );
        assert_eq!(
            check_native_pow(&header, CompactTarget::from_compact(0x207f_ffff).unwrap()),
            Err(NativePowError::InsufficientWork)
        );
    }
}
