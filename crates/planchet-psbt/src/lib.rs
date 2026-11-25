//! BIP174 v0 maps and explicit, verified P2PKH payment operations.
//!
//! With `alloc` disabled this crate has no owned API. With `alloc`, parsing and
//! forwarding preserve map order and every key/value byte, including unsupported
//! scripts, witness metadata and proprietary extensions. Parsing is not approval
//! to sign. Signing/finalization require trusted prevouts and a payment budget.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod psbt;
#[cfg(feature = "alloc")]
pub use psbt::*;
