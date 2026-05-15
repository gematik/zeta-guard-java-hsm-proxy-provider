# Phantom keys

**Problem.** JCA APIs (`Signature.initSign`, `Cipher.init`) demand a `Key` object.
But the keys live in the HSM — there is no key material to hand over.

**Mechanism.** A *phantom key* is a `Key` instance that holds no bytes:

- `HsmEcPrivateKey` implements `PrivateKey`
- `HsmSecretKey` implements `SecretKey`
- Both store only `(keyId, grpcClient)`
- Both return `null` from `getEncoded()` and a stable algorithm name
  (`"EC"` / `"AES"`)

When the JCA framework hands the key to a provider SPI (`HsmEcdsaSignatureSpi`, `HsmAesGcmCipherSpi`),
the SPI casts it back, reads `keyId` + `grpcClient`, and forwards the operation over gRPC.

**Consequence.**

- The application uses standard JCA — `Signature.getInstance(...)`, `Cipher.init(...)` — with no HSM-specific code in
  the call sites.
- A phantom key from this provider is unusable with any other provider (no encoded form to export). That is the whole
  point: keys cannot be exfiltrated through the JCA API.
- TLS stacks (Quarkus, Netty) accept these keys transparently because they only pass the key through to a `Signature`
  SPI — they never inspect the bytes.
