# Release Notes — java-hsm-proxy-provider

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
