//! Portable hashing and ECDSA verification with application-installed providers.
//!
//! SHA-256 is always available. Select `keccak`, `k256`, and/or `p256` for
//! additional algorithms, independently of `crypto-backend` registration.
//! Every provider method defaults to portable Rust software. Applications can
//! override selected operations without changing the ordinary hashing/key APIs.
//!
//! ECDSA takes an explicit 32-byte prehash and compact big-endian `r || s`.
//! Both S forms are accepted. DER decoding, hashing messages before verification,
//! signing and low-S policy belong to the caller. Only canonical, non-identity
//! compressed (33-byte) and uncompressed (65-byte) SEC1 keys are accepted.
#![no_std]
#![forbid(unsafe_code)]

use core::fmt;
use sha2::{Digest, Sha256};

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

/// Object-safe cryptographic operations used by Planchet.
///
/// Defaults call software directly, never the global provider. Overriding an
/// operation must preserve its validation and byte-order contract. Optional
/// methods follow their algorithm feature; registration enables no algorithms.
/// An adapter's feature for each override must enable the matching crate feature.
/// Additional algorithms unified by a downstream consumer use these defaults.
pub trait CryptoProvider: Sync {
    /// A single SHA-256 digest, in raw digest order.
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        Sha256::digest(input).into()
    }

    /// A single SHA-256 digest of the concatenated slices, including empty parts.
    /// The software default streams without allocating. This is not SHA256d.
    fn sha256_parts(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update(part);
        }
        hash.finalize().into()
    }

    /// Keccak-256, in raw digest order (not SHA3-256).
    #[cfg(feature = "keccak")]
    fn keccak256(&self, input: &[u8]) -> [u8; 32] {
        sha3::Keccak256::digest(input).into()
    }

    /// Validate a canonical, non-identity SEC1 secp256k1 public key.
    #[cfg(feature = "k256")]
    fn validate_k256_public_key(&self, sec1_key: &[u8]) -> Result<(), VerifyError> {
        software_k256_key(sec1_key).map(|_| ())
    }

    /// Verify compact secp256k1 ECDSA without hashing `prehash`. Accept both S forms.
    #[cfg(feature = "k256")]
    fn verify_k256_prehash(
        &self,
        sec1_key: &[u8],
        prehash: &[u8; 32],
        compact_signature: &[u8; 64],
    ) -> Result<(), VerifyError> {
        software_verify_k256(sec1_key, prehash, compact_signature)
    }

    /// Validate a canonical, non-identity SEC1 P-256 public key.
    #[cfg(feature = "p256")]
    fn validate_p256_public_key(&self, sec1_key: &[u8]) -> Result<(), VerifyError> {
        software_p256_key(sec1_key).map(|_| ())
    }

    /// Verify compact P-256 ECDSA without hashing `prehash`. Accept both S forms.
    #[cfg(feature = "p256")]
    fn verify_p256_prehash(
        &self,
        sec1_key: &[u8],
        prehash: &[u8; 32],
        compact_signature: &[u8; 64],
    ) -> Result<(), VerifyError> {
        software_verify_p256(sec1_key, prehash, compact_signature)
    }
}

/// Portable, allocation-free Rust software implementations of every enabled algorithm.
#[derive(Clone, Copy, Debug, Default)]
pub struct SoftwareCrypto;

impl CryptoProvider for SoftwareCrypto {}

static SOFTWARE_CRYPTO: SoftwareCrypto = SoftwareCrypto;

/// The installed provider, or portable software when none is installed.
///
/// Reading or using the software fallback never occupies the registration slot.
/// Without `crypto-backend`, this always returns software and needs no atomics.
#[inline]
pub fn crypto_provider() -> &'static dyn CryptoProvider {
    #[cfg(feature = "crypto-backend")]
    if let Some(provider) = registry::get() {
        return provider;
    }
    &SOFTWARE_CRYPTO
}

/// Install the application provider once. Exactly one concurrent caller succeeds.
///
/// Returns the attempted provider on failure, including reinstallation of the
/// same provider. Reads before installation do not prevent later installation.
/// Applications should install before starting cryptographic work; an operation
/// already using the software fallback may finish after installation.
/// On targets without 8-bit atomics the final application must supply a
/// `critical-section` implementation appropriate for its runtime.
#[cfg(feature = "crypto-backend")]
pub fn install_default_provider(
    provider: &'static dyn CryptoProvider,
) -> Result<(), &'static dyn CryptoProvider> {
    registry::install(provider)
}

#[cfg(all(feature = "crypto-backend", target_has_atomic = "8"))]
mod registry {
    use super::CryptoProvider;

    static PROVIDER: spin::Once<&'static dyn CryptoProvider> = spin::Once::new();

    pub(super) fn get() -> Option<&'static dyn CryptoProvider> {
        PROVIDER.get().copied()
    }

    pub(super) fn install(
        provider: &'static dyn CryptoProvider,
    ) -> Result<(), &'static dyn CryptoProvider> {
        // Checking pointer equality afterwards would incorrectly report success
        // to concurrent installers of the same provider. Only the initializer wins.
        let mut installed = false;
        PROVIDER.call_once(|| {
            installed = true;
            provider
        });
        if installed { Ok(()) } else { Err(provider) }
    }
}

#[cfg(all(feature = "crypto-backend", not(target_has_atomic = "8")))]
mod registry {
    use super::CryptoProvider;
    use core::cell::Cell;
    use critical_section::Mutex;

    static PROVIDER: Mutex<Cell<Option<&'static dyn CryptoProvider>>> = Mutex::new(Cell::new(None));

    pub(super) fn get() -> Option<&'static dyn CryptoProvider> {
        critical_section::with(|cs| PROVIDER.borrow(cs).get())
    }

    pub(super) fn install(
        provider: &'static dyn CryptoProvider,
    ) -> Result<(), &'static dyn CryptoProvider> {
        critical_section::with(|cs| {
            let slot = PROVIDER.borrow(cs);
            if slot.get().is_some() {
                Err(provider)
            } else {
                slot.set(Some(provider));
                Ok(())
            }
        })
    }
}

#[cfg(any(feature = "k256", feature = "p256"))]
fn validate_sec1_encoding(bytes: &[u8]) -> Result<(), VerifyError> {
    if matches!(
        (bytes.len(), bytes.first()),
        (33, Some(2 | 3)) | (65, Some(4))
    ) {
        Ok(())
    } else {
        Err(VerifyError::InvalidPublicKey)
    }
}

macro_rules! verifier {
    ($feature:literal, $backend:ident, $key:ident, $validate:ident, $verify:ident,
     $software_key:ident, $software_verify:ident, $normalize:expr) => {
        #[cfg(feature = $feature)]
        fn $software_key(bytes: &[u8]) -> Result<$backend::ecdsa::VerifyingKey, VerifyError> {
            validate_sec1_encoding(bytes)?;
            $backend::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map_err(|_| VerifyError::InvalidPublicKey)
        }

        #[cfg(feature = $feature)]
        fn $software_verify(
            sec1_key: &[u8],
            prehash: &[u8; 32],
            compact_signature: &[u8; 64],
        ) -> Result<(), VerifyError> {
            use $backend::ecdsa::{Signature, signature::hazmat::PrehashVerifier};
            // Preserve key-before-signature error precedence.
            let key = $software_key(sec1_key)?;
            let signature = Signature::from_slice(compact_signature)
                .map_err(|_| VerifyError::InvalidSignature)?;
            // k256 rejects high S in its trait hook. Normalize only this temporary
            // mathematical representation; wire data and caller policy stay intact.
            let signature = if $normalize {
                signature.normalize_s().unwrap_or(signature)
            } else {
                signature
            };
            key.verify_prehash(prehash, &signature)
                .map_err(|_| VerifyError::InvalidSignature)
        }

        #[cfg(feature = $feature)]
        /// A validated canonical SEC1 public key. Verification uses the current provider.
        #[derive(Clone, Eq, PartialEq)]
        pub struct $key([u8; 33]);

        #[cfg(feature = $feature)]
        impl $key {
            /// Validate using the provider and retain canonical compressed SEC1 bytes.
            pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
                $validate(bytes)?;
                let mut compressed = [0; 33];
                compressed[0] = if bytes.len() == 33 {
                    bytes[0]
                } else {
                    2 | (bytes[64] & 1)
                };
                compressed[1..].copy_from_slice(&bytes[1..33]);
                Ok(Self(compressed))
            }

            /// Verify big-endian compact `r || s` without hashing the prehash.
            /// High S is accepted; enforce signing policy in the caller.
            pub fn verify_prehash(
                &self,
                prehash: &[u8; 32],
                compact_signature: &[u8; 64],
            ) -> Result<(), VerifyError> {
                crypto_provider().$verify(&self.0, prehash, compact_signature)
            }
        }

        #[cfg(feature = $feature)]
        impl fmt::Debug for $key {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($key)).finish_non_exhaustive()
            }
        }

        #[cfg(feature = $feature)]
        /// Validate a canonical, non-identity SEC1 public key through the provider.
        pub fn $validate(sec1_key: &[u8]) -> Result<(), VerifyError> {
            validate_sec1_encoding(sec1_key)?;
            crypto_provider().$validate(sec1_key)
        }

        #[cfg(feature = $feature)]
        /// Verify SEC1 ECDSA with an explicit prehash and compact signature.
        /// Both S forms are accepted. No hashing, DER or policy processing occurs.
        pub fn $verify(
            sec1_key: &[u8],
            prehash: &[u8; 32],
            compact_signature: &[u8; 64],
        ) -> Result<(), VerifyError> {
            validate_sec1_encoding(sec1_key)?;
            crypto_provider().$verify(sec1_key, prehash, compact_signature)
        }
    };
}

verifier!(
    "k256",
    k256,
    K256VerifyingKey,
    validate_k256_public_key,
    verify_k256_prehash,
    software_k256_key,
    software_verify_k256,
    true
);
verifier!(
    "p256",
    p256,
    P256VerifyingKey,
    validate_p256_public_key,
    verify_p256_prehash,
    software_p256_key,
    software_verify_p256,
    false
);
