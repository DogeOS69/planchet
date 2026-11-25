//! Offline signing of already computed, typed 32-byte prehashes.
//!
//! `verify` exposes parsed keys/signatures and verification without a local-key
//! API, RNG, sockets or a C backend. `local` adds deterministic RFC6979 signing
//! with k256's zeroizing secret-key storage. `psbt` adds request conversion;
//! PSBT has no reverse dependency on this crate.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "verify")]
extern crate alloc;
#[cfg(feature = "verify")]
mod signing;
#[cfg(feature = "verify")]
pub use signing::*;
