/*-
* #%L
* java-hsm-proxy-provider
* %%
* (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
* %%
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* *******
*
* For additional notes and disclaimer from gematik and in case of changes by gematik
find details in the "Readme" file.
* #L%
*/
package de.gematik.zetaguard.hsmproxy

import de.gematik.zetaguard.hsmproxy.grpc.HsmProxyGrpcClient
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckResponse
import io.kotest.core.annotation.Tags
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** key_id must end with .p256 — hsm_sim derives the EC key via HKDF using this suffix */
private const val KEY_ID = "zeta-guard-keycloak-tls-es256-v1.p256"

/**
 * End-to-end integration test against hsm_sim.
 *
 * Starts the hsm_sim Docker image automatically via [HsmSim] / Docker Compose. Requires Docker to be running. Override with
 * `-Dhsm.sim.endpoint=host:port` to use an already-running instance instead (e.g. `cargo run -p hsm_sim`).
 *
 * Run with:
 * ```
 * mvn verify -Pit
 * ```
 *
 * Skipped automatically in normal `mvn verify` runs (tag excluded by default in pom.xml).
 */
@Tags("integration")
class HsmSimIntegrationTest : FunSpec() {
  private val provider = HsmProxyProvider()
  private lateinit var hsmEndpoint: String
  private lateinit var client: HsmProxyGrpcClient

  init {
    beforeSpec {
      val externalEndpoint = System.getProperty("hsm.sim.endpoint")
      if (externalEndpoint != null) {
        hsmEndpoint = externalEndpoint
      } else {
        HsmSim.start()
        hsmEndpoint = HsmSim.endpoint
      }
      Security.addProvider(provider)
      client = HsmProxyGrpcClient(hsmEndpoint)
    }

    afterSpec {
      if (::client.isInitialized) client.close()
      Security.removeProvider(HsmProxyProvider.NAME)
      HsmSim.stop()
    }

    // ── Simulator connectivity ────────────────────────────────────────────

    test("hsm_sim responds SERVING to HealthCheck") {
      val result = client.healthCheck()
      println("[IT] hsm_sim version=${result.version} hsmInfo=${result.hsmInfo}")
      result.status shouldBe HealthCheckResponse.ServingStatus.SERVING
    }

    // ── KeyStore loading ──────────────────────────────────────────────────

    test("KeyStore loads alias and fetches certificate via GetCertificate RPC") {
      val ks = loadKeyStore(hsmEndpoint, KEY_ID)

      ks.containsAlias("tls") shouldBe true
      ks.getCertificate("tls") shouldNotBe null
      println("[IT] Certificate subject: ${ks.getCertificate("tls").toString().lines().first()}")
    }

    // ── Sign + Verify ─────────────────────────────────────────────────────

    test("Signature.sign produces a DER signature verifiable with the public key from hsm_sim") {
      val ks = loadKeyStore(hsmEndpoint, KEY_ID)
      val privateKey = ks.getKey("tls", null) as PrivateKey
      val cert = ks.getCertificate("tls")

      val payload = "Hello, HSM!".toByteArray()

      // Sign using HsmProxyProvider → delegates to hsm_sim via gRPC
      val sig = Signature.getInstance(HsmProxyProvider.SIGNATURE_ALGORITHM, provider)
      sig.initSign(privateKey)
      sig.update(payload)
      val derSignature = sig.sign()

      println("[IT] DER signature (${derSignature.size} bytes): ${derSignature.toHex()}")
      derSignature.size shouldNotBe 0

      // Verify using the standard JVM provider + public key from the cert
      val verifier = Signature.getInstance(HsmProxyProvider.SIGNATURE_ALGORITHM)
      verifier.initVerify(cert)
      verifier.update(payload)
      val valid = verifier.verify(derSignature)

      println("[IT] Signature valid: $valid")
      valid shouldBe true
    }

    test("GetPublicKey returns a parseable EC public key matching the certificate") {
      val ks = loadKeyStore(hsmEndpoint, KEY_ID)
      val certPublicKey = ks.getCertificate("tls").publicKey

      val response = client.getPublicKey(KEY_ID)
      val grpcPublicKey = parsePemPublicKey(response.publicKeyPem)

      println("[IT] Public key algorithm: ${grpcPublicKey.algorithm}")
      grpcPublicKey.encoded.toHex() shouldBe certPublicKey.encoded.toHex()
    }
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

private fun loadKeyStore(endpoint: String, keyId: String): KeyStore {
  val config =
      """
    hsm.endpoint=$endpoint
    keys.tls.key_id=$keyId
    """
          .trimIndent()
  return KeyStore.getInstance(HsmProxyProvider.KEYSTORE_TYPE).apply { load(config.byteInputStream(), null) }
}

private fun parsePemPublicKey(pem: String) =
    KeyFactory.getInstance("EC")
        .generatePublic(
            X509EncodedKeySpec(
                Base64.getDecoder()
                    .decode(pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "").trim())
            )
        )

private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
