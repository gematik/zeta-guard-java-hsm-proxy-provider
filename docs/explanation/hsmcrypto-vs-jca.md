# HsmCrypto vs JCA Cipher — when to use which

This library offers two APIs for HSM-backed encryption. Pick the one that
matches the use case.

## HsmCrypto (envelope encryption)

`HsmCrypto.encrypt(plaintext)` / `.decrypt(blob)`

- One-liner calls — no `KeyStore`, no `Cipher`, no `GCMParameterSpec`.
- Reads `HSM_PROXY_ENDPOINT` and `HSM_PROXY_KEK_ID` from the environment.
  Override `keyId` per call if needed: `encrypt(plaintext, keyId = "other-kek")`.
- Returns a single `ByteArray` blob: `iv (12) || ciphertext || tag (16)`.
  Store it as-is in a database column or protobuf field.

Use this when the goal is "wrap/unwrap a DEK" or "encrypt a small secret
via the HSM". This covers the VAU database encryption use case.

## JCA Cipher SPI (TLS integration or full JCA control)

`Cipher.getInstance("AES/GCM/NoPadding")` with an `HsmSecretKey` from
`KeyStore.getInstance("HSMPROXY")`

- Standard JCA interface — integrates with frameworks that expect `Cipher`
  objects (Quarkus TLS, JSSE, custom `CipherInputStream` pipelines).
- Requires a `hsm-keystore.properties` file with `keys.<alias>.type=aes`.
- IV and ciphertext+tag are accessed separately (`cipher.iv`,
  `cipher.doFinal()`).
- AAD is set via `cipher.updateAAD(...)`.

Use this when the consumer is a framework that operates on JCA types, or
when fine-grained control over the `Cipher` lifecycle is needed.

## Under the hood

Both paths end up in the same place: `HsmProxyGrpcClient.encrypt()` /
`.decrypt()` → gRPC `Encrypt` / `Decrypt` RPC → HSM Proxy → HSM. The
difference is purely in how much ceremony the caller sees.
