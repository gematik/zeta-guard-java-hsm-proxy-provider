# java-hsm-proxy-provider

Standalone `java.security.Provider` that delegates TLS private-key operations to a remote **HSM Proxy** via gRPC.

No key material ever leaves the HSM. The provider stores only a `key_id` string and forwards all signing operations over
gRPC.

---

## Requirements

- Java 21+
- Maven 3.9+
- A running HSM Proxy exposing the gRPC API defined in [`hsm-proxy.proto`](src/main/proto/hsm-proxy.proto)

---

## Usage

**1. Create a config file** (`hsm-keystore.properties`):

```properties
hsm.endpoint=hsm-proxy:50051
keys.my-tls-key.key_id=zeta-guard-keycloak-tls-es256-v1
# cert is optional — if omitted the certificate is fetched from the HSM Proxy via GetCertificate RPC
keys.my-tls-key.cert=/etc/zeta/certs/tls.pem
```

**2. Register and load at application startup:**

```kotlin
Security.addProvider(HsmProxyProvider())

val ks = KeyStore.getInstance("HSMPROXY")
ks.load(File("hsm-keystore.properties").inputStream(), null)
```

The keystore can then be used with any standard JVM TLS configuration. Signing is routed to the HSM Proxy transparently.

**Alternative — static registration** via a custom security properties file (`-Djava.security.properties=...`):

```properties
security.provider.N=de.gematik.zetaguard.hsmproxy.HsmProxyProvider
```

The JAR includes a `META-INF/services/java.security.Provider` entry for ServiceLoader-based discovery.

---

## Example

A runnable example showing end-to-end integration is in [`example/`](./example/).

```sh
# 1. Install the library locally
mvn install -DskipTests

# 2. Start hsm_sim
cd example && docker compose up -d

# 3. Run the example (connects to localhost:15051)
mvn compile exec:java

# Custom endpoint:
mvn compile exec:java -Dexec.args="--endpoint host:port"
```

---

## Known Limitations (0.0.1)

- **EC P-256 only** — only `SHA256withECDSA` is registered. P-384 and P-521 are not yet supported.
- **Signing only** — `engineInitVerify` is not implemented. Use the standard Sun or BouncyCastle provider for signature verification (the public key is available locally from the certificate).
- **Plaintext gRPC** — the channel to the HSM Proxy is unencrypted. mTLS support is planned (requirement A_28830) and will be added in a future release.
- **No startup health-check** — the gRPC channel connects lazily on the first signing call. A misconfigured or unreachable HSM Proxy is not detected at `KeyStore.load()` time; the failure surfaces at the first TLS handshake.

---

## Build

```sh
mvn verify                                                          # compile, generate gRPC stubs, run unit tests
mvn verify -Pit                                                     # also run integration tests (starts hsm_sim via Docker/Testcontainers)
mvn verify -Pit -Dhsm.sim.endpoint=127.0.0.1:15051                 # use an already-running hsm_sim instead
mvn verify -P coverage                                              # with JaCoCo coverage report
mvn clean verify -Dspotless.skip=false -Pit
```

---

## License

(C) tech@Spree GmbH, 2026, licensed for gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License.

---

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
   1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
   2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
   3. We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to improve our processes. If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please reach out to: ospo@gematik.de
3. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
