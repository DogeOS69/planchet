//! Fixed-size hashes. Only identifiers reverse bytes at the text boundary.
use core::{fmt, str::FromStr};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// SHA-256(SHA-256(input)), in raw digest/wire order.
pub fn sha256d(input: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(input)).into()
}

/// RIPEMD-160(SHA-256(input)), in raw digest order.
pub fn hash160(input: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(input)).into()
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
