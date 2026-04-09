# Release Notes — java-hsm-proxy-provider

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
