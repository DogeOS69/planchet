//! Network identifiers and metadata pinned to Dogecoin Core v1.14.9.
//! Source: <https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/chainparams.cpp>
use crate::BlockHash;
use core::{fmt, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

/// Identity and encoding parameters, not a complete consensus validation profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainParams {
    pub network: Network,
    /// The chain name returned by Dogecoin Core RPC.
    pub core_name: &'static str,
    pub genesis_hash: BlockHash,
    pub p2pkh_prefix: u8,
    pub p2sh_prefix: u8,
    pub wif_prefix: u8,
    pub target_spacing_secs: u32,
    pub p2p_magic: [u8; 4],
    pub p2p_port: u16,
}

impl Network {
    pub const fn params(self) -> &'static ChainParams {
        match self {
            Self::Mainnet => &MAINNET,
            Self::Testnet => &TESTNET,
            Self::Regtest => &REGTEST,
        }
    }

    pub const fn genesis_hash(self) -> BlockHash {
        self.params().genesis_hash
    }

    pub const fn core_name(self) -> &'static str {
        self.params().core_name
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseNetworkError;

impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected main/mainnet, test/testnet, or regtest")
    }
}

impl core::error::Error for ParseNetworkError {}

impl FromStr for Network {
    type Err = ParseNetworkError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "main" | "mainnet" => Ok(Self::Mainnet),
            "test" | "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(ParseNetworkError),
        }
    }
}

const MAINNET: ChainParams = ChainParams {
    network: Network::Mainnet,
    core_name: "main",
    genesis_hash: BlockHash::from_wire_bytes([
        0x91, 0x56, 0x35, 0x2c, 0x18, 0x18, 0xb3, 0x2e, 0x90, 0xc9, 0xe7, 0x92, 0xef, 0xd6, 0xa1,
        0x1a, 0x82, 0xfe, 0x79, 0x56, 0xa6, 0x30, 0xf0, 0x3b, 0xbe, 0xe2, 0x36, 0xce, 0xda, 0xe3,
        0x91, 0x1a,
    ]),
    p2pkh_prefix: 30,
    p2sh_prefix: 22,
    wif_prefix: 158,
    target_spacing_secs: 60,
    p2p_magic: [0xc0, 0xc0, 0xc0, 0xc0],
    p2p_port: 22556,
};

const TESTNET: ChainParams = ChainParams {
    network: Network::Testnet,
    core_name: "test",
    genesis_hash: BlockHash::from_wire_bytes([
        0x9e, 0x55, 0x50, 0x73, 0xd0, 0xc4, 0xf3, 0x64, 0x56, 0xdb, 0x89, 0x51, 0xf4, 0x49, 0x70,
        0x4d, 0x54, 0x4d, 0x28, 0x26, 0xd9, 0xaa, 0x60, 0x63, 0x6b, 0x40, 0x37, 0x46, 0x26, 0x78,
        0x0a, 0xbb,
    ]),
    p2pkh_prefix: 113,
    p2sh_prefix: 196,
    wif_prefix: 241,
    target_spacing_secs: 60,
    p2p_magic: [0xfc, 0xc1, 0xb7, 0xdc],
    p2p_port: 44556,
};

const REGTEST: ChainParams = ChainParams {
    network: Network::Regtest,
    core_name: "regtest",
    genesis_hash: BlockHash::from_wire_bytes([
        0xa5, 0x73, 0xe9, 0x1c, 0x17, 0x72, 0x07, 0x6c, 0x0d, 0x40, 0xf7, 0x0e, 0x44, 0x08, 0xc8,
        0x3a, 0x31, 0x70, 0x5f, 0x29, 0x6a, 0xe6, 0xe7, 0x62, 0x9d, 0x4a, 0xdc, 0xb5, 0xa3, 0x60,
        0x21, 0x3d,
    ]),
    p2pkh_prefix: 111,
    p2sh_prefix: 196,
    wif_prefix: 239,
    target_spacing_secs: 1,
    p2p_magic: [0xfa, 0xbf, 0xb5, 0xda],
    p2p_port: 18444,
};
