//! Pure Rust Dogecoin types and tools. Rust 2024; MSRV 1.91.
//!
//! Default features enable `alloc`, primitives and consensus, without networking.
//! Disable defaults for the allocation-free core. `rpc` enables the provider and
//! abstract transport; `http` adds HTTP. `psbt` and `signer-local` enable offline
//! transaction/signing functionality; `signer` enables verification without local
//! private-key signing; `pow-scrypt` separately enables scrypt PoW
//! hashing. All types are reexports from their owning crates.
//!
//! `keccak` adds `keccak256`; `k256` and `p256` expose prehash verification in
//! `crypto`. The four `openvm-*` features (or `openvm` together) select guest
//! accelerators only on zkVM; native and WASM retain portable implementations.
//! Local private-key signing is a separate `signer-local` opt-in.
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
    Txid, hash160, sha256, sha256d,
};

#[cfg(feature = "rpc")]
pub use planchet_provider as provider;
#[cfg(feature = "psbt")]
pub use planchet_psbt as psbt;
#[cfg(feature = "rpc")]
pub use planchet_rpc_types as rpc_types;
#[cfg(feature = "signer")]
pub use planchet_signer as signer;
#[cfg(feature = "rpc")]
pub use planchet_transport as transport;

/// Prehashed ECDSA verification with portable byte-oriented contracts.
///
/// Curve-specific functions are enabled by `k256` and `p256`. OpenVM backend
/// features change the implementation only on `target_os = "zkvm"`.
#[cfg(any(feature = "k256", feature = "p256"))]
pub use planchet_crypto as crypto;

/// Keccak-256 (Ethereum padding, distinct from SHA3-256).
#[cfg(feature = "keccak")]
pub use primitives::keccak256;
