//! Fixed-size hashes. Only identifiers reverse bytes at the text boundary.
use core::{fmt, str::FromStr};
use ripemd::Ripemd160;
use sha2::Digest;
#[cfg(not(all(feature = "openvm-sha256", target_os = "zkvm", target_arch = "riscv32")))]
use sha2::Sha256;

/// SHA-256(input), in raw digest order.
///
/// Uses OpenVM's safe wrapper only with `openvm-sha256` on a `riscv32` zkVM.
/// Contiguous input is passed directly; the wrapper may allocate for alignment.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    #[cfg(all(feature = "openvm-sha256", target_os = "zkvm", target_arch = "riscv32"))]
    {
        openvm_sha2::sha256(input)
    }
    #[cfg(not(all(feature = "openvm-sha256", target_os = "zkvm", target_arch = "riscv32")))]
    {
        Sha256::digest(input).into()
    }
}

/// SHA-256(SHA-256(input)), in raw digest/wire order.
pub fn sha256d(input: &[u8]) -> [u8; 32] {
    sha256(&sha256(input))
}

/// SHA256d of the concatenation of `parts`, in raw digest/wire order.
///
/// Software hashing streams the slices without allocating, even with `alloc`.
/// The OpenVM backend joins multiple nonempty slices in one guest allocation
/// because its safe wrapper accepts contiguous input. Zero or one nonempty
/// slice takes the direct path. The wrapper may also allocate for alignment.
///
/// # Panics
///
/// On OpenVM, panics if the combined input length overflows `usize` or exceeds
/// vector capacity. Allocation failure is handled by the guest allocator.
pub fn sha256d_parts(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(all(feature = "openvm-sha256", target_os = "zkvm", target_arch = "riscv32"))]
    {
        let mut nonempty = parts.iter().copied().filter(|part| !part.is_empty());
        let Some(first) = nonempty.next() else {
            return sha256d(&[]);
        };
        let Some(second) = nonempty.next() else {
            return sha256d(first);
        };
        let len = parts
            .iter()
            .try_fold(0usize, |len, part| len.checked_add(part.len()))
            .expect("SHA256d input length overflows usize");
        let mut input = alloc::vec::Vec::with_capacity(len);
        input.extend_from_slice(first);
        input.extend_from_slice(second);
        for part in nonempty {
            input.extend_from_slice(part);
        }
        sha256d(&input)
    }
    #[cfg(not(all(feature = "openvm-sha256", target_os = "zkvm", target_arch = "riscv32")))]
    {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update(part);
        }
        sha256(&hash.finalize())
    }
}

/// RIPEMD-160(SHA-256(input)), in raw digest order.
pub fn hash160(input: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(input)).into()
}

/// Keccak-256(input), in raw digest order. This is not SHA3-256.
///
/// Uses OpenVM's safe wrapper only with `openvm-keccak256` on a `riscv32` zkVM;
/// that wrapper may allocate for alignment. Other targets use portable Rust.
#[cfg(feature = "keccak")]
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    #[cfg(all(
        feature = "openvm-keccak256",
        target_os = "zkvm",
        target_arch = "riscv32"
    ))]
    {
        openvm_keccak256::keccak256(input)
    }
    #[cfg(not(all(
        feature = "openvm-keccak256",
        target_os = "zkvm",
        target_arch = "riscv32"
    )))]
    {
        sha3::Keccak256::digest(input).into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseHashError {
    InvalidLength { expected: usize, actual: usize },
    InvalidHex { index: usize },
}

impl fmt::Display for ParseHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} hex bytes, got {actual}")
            }
            Self::InvalidHex { index } => write!(f, "invalid hex at byte {index}"),
        }
    }
}

impl core::error::Error for ParseHashError {}

fn nibble(byte: u8, index: usize) -> Result<u8, ParseHashError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ParseHashError::InvalidHex { index }),
    }
}

fn parse<const N: usize>(text: &str, reversed: bool) -> Result<[u8; N], ParseHashError> {
    if text.len() != N * 2 {
        return Err(ParseHashError::InvalidLength {
            expected: N * 2,
            actual: text.len(),
        });
    }
    let mut bytes = [0; N];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let value = nibble(pair[0], i * 2)? << 4 | nibble(pair[1], i * 2 + 1)?;
        bytes[if reversed { N - 1 - i } else { i }] = value;
    }
    Ok(bytes)
}

macro_rules! hash_type {
    ($name:ident, $len:expr, $reversed:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const ZERO: Self = Self([0; $len]);

            /// Construct from raw digest bytes, in wire order for IDs.
            pub const fn from_wire_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn to_wire_bytes(self) -> [u8; $len] {
                self.0
            }

            pub const fn as_wire_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ParseHashError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                parse(text, $reversed).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for i in 0..$len {
                    let byte = self.0[if $reversed { $len - 1 - i } else { i }];
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }
    };
}

hash_type!(
    Txid,
    32,
    true,
    "Transaction identifier; text uses reversed wire bytes."
);
hash_type!(
    BlockHash,
    32,
    true,
    "Block identifier; text uses reversed wire bytes."
);
hash_type!(
    MerkleRoot,
    32,
    true,
    "Transaction Merkle root; text uses reversed wire bytes."
);
hash_type!(
    Sighash,
    32,
    false,
    "Signing prehash; text preserves raw digest order."
);
hash_type!(
    Hash160,
    20,
    false,
    "Public-key or script HASH160; text preserves digest order."
);

macro_rules! rpc_hex {
    ($($name:ident),+ $(,)?) => {$ (
        impl $name {
            /// Parse exactly 64 RPC/display hex characters, reversing once.
            pub fn from_rpc_hex(text: &str) -> Result<Self, ParseHashError> {
                text.parse()
            }
        }
    )+ };
}
rpc_hex!(Txid, BlockHash, MerkleRoot);
