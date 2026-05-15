# Exception mapping

The provider maps gRPC and configuration failures onto the standard JCA exception hierarchy, so callers don't need to
depend on gRPC types.

| Operation                          | Failure                                                                                 | Thrown                                                               |
|------------------------------------|-----------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| `KeyStore.load`                    | `hsm.endpoint` missing, unknown `type`, cert PEM unreadable, `GetCertificate` RPC fails | `KeyStoreException`                                                  |
| `KeyStore.set*` / `delete*`        | any                                                                                     | `UnsupportedOperationException` (read-only)                          |
| `Signature.initSign`               | key is not an `HsmEcPrivateKey`                                                         | `InvalidKeyException`                                                |
| `Signature.initVerify`             | always                                                                                  | `UnsupportedOperationException` (use a standard provider for verify) |
| `Signature.sign`                   | gRPC `Sign` failure (incl. unreachable HSM, wrong key_id)                               | `SignatureException` (cause = original exception)                    |
| `Cipher.init`                      | key is not an `HsmSecretKey`                                                            | `InvalidKeyException`                                                |
| `Cipher.init`                      | `params` is not a `GCMParameterSpec`                                                    | `InvalidAlgorithmParameterException`                                 |
| `Cipher.doFinal` (encrypt/decrypt) | gRPC failure, GCM tag mismatch, AAD mismatch, ciphertext < 16 bytes                     | `BadPaddingException` (cause = original exception)                   |
| `Cipher.setMode` / `setPadding`    | not `GCM` / `NoPadding`                                                                 | `UnsupportedOperationException`                                      |

## Distinguishing causes

`BadPaddingException` deliberately collapses several distinct conditions because callers normally treat them all as
"decrypt failed".
To differentiate (e.g. retry on transient HSM unavailability vs. fail hard on tag mismatch),
inspect `cause` — it carries the original `StatusRuntimeException` from gRPC, whose `Status.Code` distinguishes
`UNAVAILABLE` (network) from `INVALID_ARGUMENT` (auth tag) etc.
