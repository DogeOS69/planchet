//! Bounded, byte-preserving Dogecoin wire views. Rust 2024, MSRV 1.91.
//!
//! All borrowed decoders, iterators, hashes and Merkle checks work without
//! `std` or `alloc`. `alloc` (default) enables the separately maintained owned
//! transaction and signing modules; `std` implies `alloc`. Dependencies use
//! pure Rust implementations, including software SHA-256.
//!
//! Decoding establishes wire structure and resource bounds, not script validity,
//! difficulty, parent-chain commitments, or complete AuxPoW/chain consensus.
//! Limits are application budgets, not network consensus constants.
//!
//! ```
//! use planchet_consensus::{BlockRef, DecodeLimits};
//! use planchet_primitives::BlockHash;
//! # let raw = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/regtest-genesis.bin"));
//! let block = BlockRef::decode_exact(raw, DecodeLimits::default()).unwrap();
//! let id: BlockHash = block.header().block_id();
//! block.check_tx_merkle_root().unwrap();
//! let mut encoded = [0u8; 80];
//! assert_eq!(block.header().encode_into(&mut encoded).unwrap(), 80);
//! assert_eq!(&encoded, &raw[..80]);
//! for tx in block.transactions() {
//!     for output in tx.outputs() {
//!         assert_eq!(output.script_pubkey(), &tx.bytes()[output.script_pubkey_range()]);
//!     }
//! }
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod block;
pub mod borrowed;
pub mod compact_size;
pub mod decode;
pub mod header;
pub mod inclusion;
pub mod merkle;
pub mod pow;
pub mod script;
#[cfg(feature = "alloc")]
pub mod sighash;
#[cfg(feature = "alloc")]
pub mod transaction;

pub use block::{BlockRef, Transactions, Txids};
pub use borrowed::{Inputs, Outputs, TxInRef, TxOutRef, TxRef};
pub use decode::{DecodeError, DecodeLimits};
pub use header::{AuxPowRef, BaseHeader, MerkleBranch, ParentCoinbaseRef, WireHeader};
pub use inclusion::{
    InclusionError, MatchedTransactions, MerkleBlockRef, PartialMerkleError, PartialMerkleTreeRef,
    VerifiedPartialMerkleTree, verify_inclusion,
};
pub use merkle::{MerkleError, merkle_root_checked};
