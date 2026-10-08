# Release Notes — java-hsm-proxy-provider

## Release 1.0.3

### changed

- Build now runs the `maven-shade-plugin` with a `ServicesResourceTransformer`, merging the `META-INF/services`
  provider-registration entries into the packaged artifact. Required so the provider registers correctly when the JAR is
  bundled alongside Infinispan and other HSM dependencies.

## Release 1.0.2

### added

- `Signature.SHA256withECDSAinP1363Format` — raw 64-byte R‖S output (no DER wrapping). Required by the JDK's TLS 1.3
  `ecdsa_secp256r1_sha256` SignatureScheme. Without it, TLS 1.3 handshakes against HSM-backed certs silently fail
  (server closes after ClientHello with no compatible signature scheme).

### changed

- `HsmEcPrivateKey.getEncoded()` placeholder is now generated via `KeyPairGenerator.getInstance("EC", "SunEC")`. Without
  an explicit provider, BouncyCastle can win and emit EC PKCS#8 with optional fields that SUN PKCS12's `getKey` rejects
  with `extra data at the end`.

## Release 1.0.1

### changed

- `HsmEcPrivateKey.getEncoded()` returns a throwaway P-256 PKCS#8 placeholder instead of `null` — unblocks Vert.x
  `KeyStoreHelper` SNI re-pack on Quarkus ≥ 3.31. HSM-backed signing path unchanged.

## Release 1.0.0

### changed

- Version bump only — no functional changes vs. 0.2.2.

## Release 0.2.2

### added

- `Signature.SHA256withECDSA` advertises `SupportedKeyClasses=HsmEcPrivateKey` — enables JCE auto-resolution to
  `HSMPROXY` for callers that invoke `Signature.getInstance("SHA256withECDSA")` **without** an explicit provider.
- `HsmEcPrivateKey` now implements `java.security.interfaces.ECPrivateKey` and exposes the curve `ECParameterSpec` (read
  from the public certificate). `getS()` throws `UnsupportedOperationException` — the private scalar never leaves the
  HSM.

### changed

- `HsmProxyProvider` registers all three services (`KeyStore`, `Signature`, `Cipher`) via `putService(Service(...))`
  instead of the legacy `put("…", className)` form. `Service` instances allow per-algorithm attributes such as
  `SupportedKeyClasses`.
- `HsmKeyStoreSpi.engineGetKey` now throws a typed `KeyStoreException` (instead of `ClassCastException`) when the
  certificate configured for an `EC` alias is not an EC certificate.

## Release 0.2.1

### fixed

- `HsmEcPrivateKey.getFormat()` returns `"PKCS#8"` instead of `null`

## Release 0.2.0

### added

- `HsmCrypto` — simplified encrypt/decrypt API (one-liner, env-var driven)
- `Cipher.AES/GCM/NoPadding` backed by HSM Proxy `Encrypt` / `Decrypt`
- `keys.<alias>.type=aes` KeyStore config for symmetric keys

## Release 0.1.0

### added

- Support env-var fallback

## Release 0.0.1

### added

- `java.security.Provider` registering `KeyStore.HSMPROXY` and `Signature.SHA256withECDSA`
- KeyStore loads key references from a `.properties` stream; certificates fetched via `GetCertificate` RPC if no PEM
  file configured
- Signing delegates to HSM Proxy via gRPC — no key material leaves the HSM
- Integration tests against `hsm_sim` via Testcontainers
- Example application in `example/`
