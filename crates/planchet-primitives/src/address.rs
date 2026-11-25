//! Network-bound P2PKH and P2SH Base58Check addresses; no allocation required.
use crate::{Hash160, Network, sha256d};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AddressKind {
    P2pkh,
    P2sh,
}

/// An address bound to a caller-selected network.
///
/// Testnet and regtest share P2SH encodings. Parsing proves the encoding is valid
/// for the supplied network; it cannot prove which chain an address came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Address {
    network: Network,
    kind: AddressKind,
    payload: Hash160,
}

impl Address {
    pub const fn p2pkh(network: Network, pubkey_hash: Hash160) -> Self {
        Self {
            network,
            kind: AddressKind::P2pkh,
            payload: pubkey_hash,
        }
    }

    pub const fn p2sh(network: Network, script_hash: Hash160) -> Self {
        Self {
            network,
            kind: AddressKind::P2sh,
            payload: script_hash,
        }
    }

    pub const fn network(self) -> Network {
        self.network
    }
    pub const fn kind(self) -> AddressKind {
        self.kind
    }
    pub const fn payload(self) -> Hash160 {
        self.payload
    }

    /// Parse a canonical address for exactly the requested network. No retries,
    /// whitespace, unbounded allocation or network inference are performed.
    pub fn parse(text: &str, network: Network) -> Result<Self, AddressError> {
        if text.is_empty() || text.len() > 35 {
            return Err(AddressError::InvalidLength);
        }
        let mut bytes = [0u8; 25];
        let len = bs58::decode(text)
            .onto(&mut bytes)
            .map_err(|error| match error {
                bs58::decode::Error::BufferTooSmall => AddressError::InvalidLength,
                _ => AddressError::InvalidBase58,
            })?;
        if len != bytes.len() {
            return Err(AddressError::InvalidLength);
        }
        if sha256d(&bytes[..21])[..4] != bytes[21..] {
            return Err(AddressError::InvalidChecksum);
        }
        let params = network.params();
        let kind = if bytes[0] == params.p2pkh_prefix {
            AddressKind::P2pkh
        } else if bytes[0] == params.p2sh_prefix {
            AddressKind::P2sh
        } else {
            return Err(AddressError::WrongNetwork {
                expected: network,
                version: bytes[0],
            });
        };
        let mut payload = [0; 20];
        payload.copy_from_slice(&bytes[1..21]);
        Ok(Self {
            network,
            kind,
            payload: Hash160::from_wire_bytes(payload),
        })
    }

    /// The exact 25-byte Base58Check payload, including its four checksum bytes.
    pub fn to_base58check_bytes(self) -> [u8; 25] {
        let mut bytes = [0; 25];
        bytes[0] = match self.kind {
            AddressKind::P2pkh => self.network.params().p2pkh_prefix,
            AddressKind::P2sh => self.network.params().p2sh_prefix,
        };
        bytes[1..21].copy_from_slice(self.payload.as_wire_bytes());
        let checksum = sha256d(&bytes[..21]);
        bytes[21..].copy_from_slice(&checksum[..4]);
        bytes
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buffer = [0; 40];
        let len = bs58::encode(self.to_base58check_bytes())
            .onto(&mut buffer[..])
            .map_err(|_| fmt::Error)?;
        f.write_str(core::str::from_utf8(&buffer[..len]).map_err(|_| fmt::Error)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    InvalidLength,
    InvalidBase58,
    InvalidChecksum,
    WrongNetwork { expected: Network, version: u8 },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("expected a 25-byte Base58Check address"),
            Self::InvalidBase58 => f.write_str("invalid Base58 address alphabet"),
            Self::InvalidChecksum => f.write_str("invalid Base58Check checksum"),
            Self::WrongNetwork { expected, version } => write!(
                f,
                "address version {version:#04x} is not valid for {expected}"
            ),
        }
    }
}

impl core::error::Error for AddressError {}
