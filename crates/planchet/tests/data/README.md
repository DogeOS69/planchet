# Public payment integration fixtures

These are the user-supplied Dogecoin Core 1.14.9 regtest qualification fixtures.
The funding transaction and independently signed, Core-accepted payment are
preserved byte-for-byte. No private keys are included.

The payment spends parent output 0 (200,000,000 koinu), pays 199,000,000 koinu
and has a 1,000,000 koinu fee.

| File | RPC txid | SHA-256 of file bytes |
| --- | --- | --- |
| `payment-parent.bin` (226 bytes) | `e6c776786ea59351c0c0dd43c3c0e1fb3accc656c4909a85e2c7df323df289d5` | `25d375029b70c6139e7ba83d97ffd1176a5c46c4088533d9e355e24884554dcc` |
| `payment-signed.bin` (192 bytes) | `3cd139ff08015a742456f341bd5a6105954bef85c69ad3e581c429454b8e844a` | `f0b9d0e1011d4b273410bd83d89b7fd35df760f28955bc55bff1917bfb7bf7de` |

The high-S DER constant in `provider_payment.rs` preserves the payment's r and
replaces s with n - s, using the standard secp256k1 scalar order
`fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`.
It was computed independently using Python integer subtraction. Both forms
satisfy the same ECDSA equation; only low S meets current signing policy.

`provider_hashes.rs` runs with only `crypto-backend` enabled. The payment test
runs with `psbt,signer`, both with and without provider registration. Separate
test executables keep their process-wide provider installations independent.
