//! Curve-only ECDSA verification over explicit 32-byte prehashes.
//!
//! Select `k256` and/or `p256`. `openvm-k256` and `openvm-p256` additionally
//! select upstream OpenVM verification and SEC1 decoding on `target_os = "zkvm"`
//! with `target_arch = "riscv32"`.
//! Other targets always use RustCrypto, including with every feature enabled.
//! No message hashing, DER decoding, signing, or transaction policy lives here.
//!
//! Both S forms are mathematically valid. Callers enforce low-S policy and DER
//! rules before passing compact, big-endian `r || s` signatures to this crate.
//! Only compressed (33-byte) and uncompressed (65-byte) SEC1 keys are accepted.
//! Identity, off-curve points, noncanonical coordinates, zero/out-of-range
//! scalars, and failed verification return errors.
#![no_std]
#![forbid(unsafe_code)]

use core::fmt;

#[cfg(all(
    feature = "k256",
    not(all(target_os = "zkvm", target_arch = "riscv32", feature = "openvm-k256"))
))]
use k256 as k256_backend;
#[cfg(all(target_os = "zkvm", target_arch = "riscv32", feature = "openvm-k256"))]
use openvm_k256 as k256_backend;
#[cfg(all(target_os = "zkvm", target_arch = "riscv32", feature = "openvm-p256"))]
use openvm_p256 as p256_backend;
#[cfg(all(
    feature = "p256",
    not(all(target_os = "zkvm", target_arch = "riscv32", feature = "openvm-p256"))
))]
use p256 as p256_backend;

/// Failure to decode a public key or verify an ECDSA signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    InvalidPublicKey,
    InvalidSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPublicKey => "invalid SEC1 public key",
            Self::InvalidSignature => "invalid ECDSA signature",
        })
    }
}

impl core::error::Error for VerifyError {}

// Keep the cached validated key backend-independent, so callers do not have to
// decode a software ECC key before entering the accelerated verifier.
macro_rules! verifier {
    ($feature:literal, $backend:ident, $key:ident, $verify:ident, $normalize:expr) => {
        #[cfg(feature = $feature)]
        /// A cached, validated public key using the selected curve backend.
        #[derive(Clone)]
        pub struct $key($backend::ecdsa::VerifyingKey);

        #[cfg(feature = $feature)]
        impl $key {
            /// Decode a canonical, non-identity SEC1 point on the selected curve.
            pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
                if !matches!(
                    (bytes.len(), bytes.first()),
                    (33, Some(2 | 3)) | (65, Some(4))
                ) {
                    return Err(VerifyError::InvalidPublicKey);
                }
                $backend::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                    .map(Self)
                    .map_err(|_| VerifyError::InvalidPublicKey)
            }

            /// Verify big-endian compact `r || s` without hashing the prehash.
            /// High S is accepted; enforce signing policy in the caller.
            pub fn verify_prehash(
                &self,
                prehash: &[u8; 32],
                compact_signature: &[u8; 64],
            ) -> Result<(), VerifyError> {
                use $backend::ecdsa::{Signature, signature::hazmat::PrehashVerifier};
                let signature = Signature::from_slice(compact_signature)
                    .map_err(|_| VerifyError::InvalidSignature)?;
                // Both k256 backends reject high S in their trait hook. Normalize
                // only this temporary mathematical representation, never wire data.
                let signature = if $normalize {
                    signature.normalize_s().unwrap_or(signature)
                } else {
                    signature
                };
                self.0
                    .verify_prehash(prehash, &signature)
                    .map_err(|_| VerifyError::InvalidSignature)
            }
        }

        #[cfg(feature = $feature)]
        impl fmt::Debug for $key {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($key)).finish_non_exhaustive()
            }
        }

        #[cfg(feature = $feature)]
        impl PartialEq for $key {
            fn eq(&self, other: &Self) -> bool {
                self.0.as_affine() == other.0.as_affine()
            }
        }

        #[cfg(feature = $feature)]
        impl Eq for $key {}

        #[cfg(feature = $feature)]
        /// Verify ECDSA using an explicit SEC1 public key, a 32-byte prehash,
        /// and a 64-byte big-endian compact signature. Both S forms are accepted.
        /// No hashing or DER/policy processing is performed.
        pub fn $verify(
            sec1_key: &[u8],
            prehash: &[u8; 32],
            compact_signature: &[u8; 64],
        ) -> Result<(), VerifyError> {
            $key::from_sec1_bytes(sec1_key)?.verify_prehash(prehash, compact_signature)
        }
    };
}

verifier!(
    "k256",
    k256_backend,
    K256VerifyingKey,
    verify_k256_prehash,
    true
);
verifier!(
    "p256",
    p256_backend,
    P256VerifyingKey,
    verify_p256_prehash,
    false
);
