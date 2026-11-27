use alloc::vec::Vec;
use core::fmt;
use k256::ecdsa::Signature;
use planchet_consensus::{
    script::match_p2pkh,
    sighash::{SighashError, SighashType, legacy_sighash_for_signing},
    transaction::{PaymentBudget, PaymentError, Prevout, Transaction},
};
use planchet_crypto::{validate_k256_public_key, verify_k256_prehash};
use planchet_primitives::{Sighash, hash160};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidDer,
    HighS,
    InvalidSignature,
    WrongPublicKey,
    WrongMode,
    UnsupportedTemplate,
    SignedTransaction,
    Payment(PaymentError),
    Sighash(SighashError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}
impl From<PaymentError> for Error {
    fn from(error: PaymentError) -> Self {
        Self::Payment(error)
    }
}
impl From<SighashError> for Error {
    fn from(error: SighashError) -> Self {
        Self::Sighash(error)
    }
}

/// A validated compressed or uncompressed SEC1 public key, retaining the exact
/// encoding which commits to the P2PKH HASH160.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    bytes: Vec<u8>,
}
impl PublicKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
        validate_k256_public_key(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self {
            bytes: bytes.into(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Parsed strict DER without a trailing sighash byte. Parsing historical DER
/// does not silently change high S or rewrite a historical transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcdsaSignature {
    der: Vec<u8>,
    signature: Signature,
}
impl EcdsaSignature {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let signature = Signature::from_der(der).map_err(|_| Error::InvalidDer)?;
        if signature.to_der().as_bytes() != der {
            return Err(Error::InvalidDer);
        }
        Ok(Self {
            der: der.into(),
            signature,
        })
    }
    pub fn from_low_s_der(der: &[u8]) -> Result<Self, Error> {
        let parsed = Self::from_der(der)?;
        if !parsed.is_low_s() {
            return Err(Error::HighS);
        }
        Ok(parsed)
    }
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
    pub fn is_low_s(&self) -> bool {
        self.signature.normalize_s().is_none()
    }
}

/// Mathematical ECDSA verification of a historical strict-DER signature.
/// High S is accepted by normalizing a temporary scalar representation only;
/// the parsed bytes remain untouched. This is not a full historical Script VM
/// or a lax pre-BIP66 signature decoder.
pub fn verify_historical(
    public_key: &PublicKey,
    digest: Sighash,
    signature: &EcdsaSignature,
) -> Result<(), Error> {
    let mathematical = signature
        .signature
        .normalize_s()
        .unwrap_or(signature.signature);
    let compact = mathematical.to_bytes().into();
    verify_k256_prehash(public_key.as_bytes(), digest.as_wire_bytes(), &compact)
        .map_err(|_| Error::InvalidSignature)
}

/// Current signing policy: strict DER, valid curve scalars and low S.
pub fn verify_prehash(
    public_key: &PublicKey,
    digest: Sighash,
    signature: &EcdsaSignature,
) -> Result<(), Error> {
    if !signature.is_low_s() {
        return Err(Error::HighS);
    }
    verify_historical(public_key, digest, signature)
}

/// A contextual, checked request; arbitrary digests cannot be promoted to
/// authorized P2PKH requests through public field mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignRequest {
    digest: Sighash,
    public_key: PublicKey,
    sighash_type: SighashType,
}
impl SignRequest {
    pub fn p2pkh(
        tx: &Transaction,
        input_index: usize,
        prevouts: &[Prevout],
        public_key: PublicKey,
        sighash_type: SighashType,
        budget: PaymentBudget,
    ) -> Result<Self, Error> {
        if tx.inputs.iter().any(|input| !input.script_sig.is_empty()) {
            return Err(Error::SignedTransaction);
        }
        let prevout = prevouts.get(input_index).ok_or(SighashError::InputIndex)?;
        if match_p2pkh(&prevout.output.script_pubkey).map(|h| h.to_wire_bytes())
            != Some(hash160(public_key.as_bytes()))
        {
            return Err(Error::UnsupportedTemplate);
        }
        let mut largest = tx.clone();
        for input in &mut largest.inputs {
            input.script_sig = alloc::vec![0; 139];
        }
        budget.check(tx, prevouts, largest.encode().len())?;
        let digest = legacy_sighash_for_signing(
            tx,
            input_index,
            &prevout.output.script_pubkey,
            sighash_type,
        )?;
        Ok(Self {
            digest,
            public_key,
            sighash_type,
        })
    }

    #[cfg(feature = "psbt")]
    pub fn from_psbt(request: &planchet_psbt::P2pkhSignRequest) -> Result<Self, Error> {
        Ok(Self {
            digest: request.digest(),
            public_key: PublicKey::from_sec1_bytes(request.public_key())?,
            sighash_type: request.sighash_type(),
        })
    }
    pub fn digest(&self) -> Sighash {
        self.digest
    }
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn sighash_type(&self) -> SighashType {
        self.sighash_type
    }

    /// Validate the returned key, mode, digest and low-S signature before use.
    pub fn validate_result(&self, result: &SignerResult) -> Result<(), Error> {
        if result.public_key != self.public_key {
            return Err(Error::WrongPublicKey);
        }
        if result.sighash_type != self.sighash_type {
            return Err(Error::WrongMode);
        }
        verify_prehash(&self.public_key, self.digest, &result.signature)
    }
}

/// An external response can be parsed independently, but it is not authorized
/// until `SignRequest::validate_result` (and PSBT insertion) succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerResult {
    pub public_key: PublicKey,
    pub signature: EcdsaSignature,
    pub sighash_type: SighashType,
}

/// Adapter boundary for offline, hardware or remote signers. Applications may
/// wrap this synchronous contract in their own asynchronous transport API.
pub trait DigestSigner {
    type Error;
    fn sign_prehash(&self, request: &SignRequest) -> Result<SignerResult, Self::Error>;
}

#[cfg(feature = "local")]
pub struct LocalSigner {
    key: k256::ecdsa::SigningKey,
    compressed: bool,
}

#[cfg(feature = "local")]
impl fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalSigner([REDACTED])")
    }
}

#[cfg(feature = "local")]
impl LocalSigner {
    /// The key is copied into k256's zeroizing key storage. The caller is still
    /// responsible for zeroizing its own input buffer after this returns.
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, Error> {
        let key =
            k256::ecdsa::SigningKey::from_slice(secret).map_err(|_| Error::InvalidSecretKey)?;
        Ok(Self {
            key,
            compressed: true,
        })
    }
    pub fn with_compressed_public_key(mut self, compressed: bool) -> Self {
        self.compressed = compressed;
        self
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            bytes: self
                .key
                .verifying_key()
                .to_encoded_point(self.compressed)
                .as_bytes()
                .into(),
        }
    }
}

#[cfg(feature = "local")]
impl DigestSigner for LocalSigner {
    type Error = Error;
    fn sign_prehash(&self, request: &SignRequest) -> Result<SignerResult, Self::Error> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        if self.public_key() != request.public_key {
            return Err(Error::WrongPublicKey);
        }
        // PrehashSigner is essential: Signer would SHA-256 this digest again.
        let signature: Signature = self
            .key
            .sign_prehash(request.digest.as_ref())
            .map_err(|_| Error::InvalidSignature)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let result = SignerResult {
            public_key: self.public_key(),
            signature: EcdsaSignature::from_low_s_der(signature.to_der().as_bytes())?,
            sighash_type: request.sighash_type,
        };
        request.validate_result(&result)?;
        Ok(result)
    }
}

#[cfg(all(test, feature = "local"))]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    // Dogecoin v1.14.9 src/test/key_tests.cpp, deterministic signing example.
    // Test scalar decoded from its public strSecret1 WIF. Expected signature
    // is copied from Core; the prehash is SHA256d("Very deterministic message").
    // This catches an accidental second hash or a different RFC6979 input.
    #[test]
    fn independent_core_deterministic_prehash_signature() {
        let secret = hex("0f6055b44781882c04d6683d8e11a8282d068ef139a78f9d45e9ba290d1ce25f")
            .try_into()
            .unwrap();
        let signer = LocalSigner::from_bytes(&secret).unwrap();
        let request = SignRequest {
            digest: Sighash::from_wire_bytes(
                hex("5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a")
                    .try_into()
                    .unwrap(),
            ),
            public_key: signer.public_key(),
            sighash_type: SighashType::All,
        };
        let result = signer.sign_prehash(&request).unwrap();
        assert_eq!(
            result.signature.as_der(),
            hex(
                "3044022030475ecf08b2c234a0f1ecfdb65871e4e6a419a995e667ce8bc2c331b916c2df02200b6dffef4a9fb2528a7f65f6e780583ba874618d4a141415dfb65f2f4bb833be"
            )
        );
        assert!(result.signature.is_low_s());
        assert_eq!(alloc::format!("{signer:?}"), "LocalSigner([REDACTED])");
        assert!(LocalSigner::from_bytes(&[0; 32]).is_err());
        assert!(LocalSigner::from_bytes(&[0xff; 32]).is_err());
    }
}
