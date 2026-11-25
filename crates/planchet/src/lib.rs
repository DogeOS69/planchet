//! Pure Rust Dogecoin types and tools. Rust 2024; MSRV 1.91.
//!
//! Default features enable `alloc`, primitives and consensus, without networking.
//! Disable defaults for the allocation-free core. `rpc` enables the provider and
//! abstract transport; `http` adds HTTP. `psbt` and `signer-local` enable offline
//! transaction/signing functionality; `pow-scrypt` separately enables native PoW
//! hashing. All types are reexports from their owning crates.
//!
//! ```
//! use planchet::{Address, Amount, FeeRate, Hash160, Network};
//!
//! let amount = Amount::from_doge_str("1.25")?;
//! assert_eq!(amount.to_koinu(), 125_000_000);
//! let fee = FeeRate::from_koinu_per_kvb(1_000).fee_for_bytes(250).unwrap();
//! assert_eq!(fee.to_koinu(), 250);
//! let address = Address::p2pkh(Network::Mainnet, Hash160::ZERO);
//! assert_eq!(Address::parse(&address.to_string(), Network::Mainnet)?, address);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub use consensus::{BaseHeader, BlockRef, DecodeError, DecodeLimits, TxRef, WireHeader};
pub use planchet_consensus as consensus;
pub use planchet_primitives as primitives;
pub use primitives::{
    Address, AddressError, AddressKind, Amount, BlockHash, ChainParams, FeeRate, Hash160,
    MerkleRoot, Network, OutPoint, ParseAmountError, ParseHashError, ParseNetworkError, Sighash,
    Txid, hash160, sha256d,
};

#[cfg(feature = "rpc")]
pub use planchet_provider as provider;
#[cfg(feature = "psbt")]
pub use planchet_psbt as psbt;
#[cfg(feature = "rpc")]
pub use planchet_rpc_types as rpc_types;
#[cfg(feature = "signer-local")]
pub use planchet_signer as signer;
#[cfg(feature = "rpc")]
pub use planchet_transport as transport;
