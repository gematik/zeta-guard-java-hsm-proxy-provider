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
package de.gematik.zetaguard.hsmproxy.keystore

import com.google.protobuf.ByteString
import de.gematik.zetaguard.hsmproxy.grpc.HsmProxyGrpcClient
import de.gematik.zetaguard.hsmproxy.v1.GetCertificateRequest
import de.gematik.zetaguard.hsmproxy.v1.GetCertificateResponse
import de.gematik.zetaguard.hsmproxy.v1.HsmProxyServiceGrpc
import de.gematik.zetaguard.hsmproxy.v1.SignRequest
import de.gematik.zetaguard.hsmproxy.v1.SignResponse
import io.grpc.ManagedChannel
import io.grpc.Server
import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import io.grpc.stub.StreamObserver
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.io.File
import java.security.KeyStoreException
import java.security.cert.X509Certificate

class HsmKeyStoreSpiTest : FunSpec() {
  private lateinit var certFile: File
  private lateinit var cert: X509Certificate

  init {
    beforeSpec {
      val (generatedCert, generatedFile) = TestCertificateFactory.generateSelfSignedEcCert()
      cert = generatedCert
      certFile = generatedFile
    }

    afterSpec { if (::certFile.isInitialized) certFile.delete() }

    // ── helpers ───────────────────────────────────────────────────────────

    fun config(
        endpoint: String = "localhost:50051",
        alias: String = "tls-key",
        keyId: String = "zeta-guard-tls-es256-v1",
        certPath: String = certFile.absolutePath,
    ) =
        """
        hsm.endpoint=$endpoint
        keys.$alias.key_id=$keyId
        keys.$alias.cert=$certPath
        """
            .trimIndent()

    fun loadSpi(cfg: String): HsmKeyStoreSpi {
      val spi = HsmKeyStoreSpi()
      spi.engineLoad(cfg.byteInputStream(), null)
      return spi
    }

    fun loadSpiWithChannel(cfg: String, channel: ManagedChannel): HsmKeyStoreSpi {
      val spi = FakeChannelHsmKeyStoreSpi(channel)
      spi.engineLoad(cfg.byteInputStream(), null)
      return spi
    }

    // ── engineLoad ────────────────────────────────────────────────────────

    test("engineLoad accepts valid config without error") {
      loadSpi(config()) // must not throw
    }

    test("engineLoad creates gRPC client with configured endpoint") {
      val spi = loadSpi(config(endpoint = "hsm-proxy:50051"))
      spi.grpcClient.shouldNotBeNull()
    }

    test("engineLoad throws KeyStoreException when hsm.endpoint is missing") {
      val cfg = "keys.tls-key.key_id=some-id\nkeys.tls-key.cert=${certFile.absolutePath}"
      shouldThrow<KeyStoreException> { loadSpi(cfg) }
    }

    test("engineLoad throws KeyStoreException when cert path does not exist") {
      val cfg = config(certPath = "/nonexistent/path/cert.pem")
      shouldThrow<KeyStoreException> { loadSpi(cfg) }
    }

    // ── engineLoad — gRPC cert path ────────────────────────────────────────

    test("engineLoad fetches certificate from gRPC when cert path is absent") {
      val (grpcCert, server, channel) = startFakeGrpcServer()
      try {
        val cfg =
            """
            hsm.endpoint=unused
            keys.tls-key.key_id=zeta-guard-tls-es256-v1.p256
            """
                .trimIndent()
        val spi = loadSpiWithChannel(cfg, channel)
        val loaded = spi.engineGetCertificate("tls-key")
        loaded.shouldBeInstanceOf<X509Certificate>()
        loaded shouldBe grpcCert
      } finally {
        channel.shutdown()
        server.shutdown()
      }
    }

    test("engineLoad throws KeyStoreException when gRPC cert fetch fails") {
      val (_, server, channel) = startFakeGrpcServer(error = Status.NOT_FOUND.asRuntimeException())
      try {
        val cfg =
            """
            hsm.endpoint=unused
            keys.tls-key.key_id=zeta-guard-tls-es256-v1.p256
            """
                .trimIndent()
        shouldThrow<KeyStoreException> { loadSpiWithChannel(cfg, channel) }
      } finally {
        channel.shutdown()
        server.shutdown()
      }
    }

    test("engineLoad throws KeyStoreException when stream is null and env vars are absent") {
      shouldThrow<KeyStoreException> { HsmKeyStoreSpi().engineLoad(null, null) }
    }

    test("engineLoad throws KeyStoreException when stream is empty and env vars are absent") {
      shouldThrow<KeyStoreException> { HsmKeyStoreSpi().engineLoad("".byteInputStream(), null) }
    }

    // ── engineLoad — env-var fallback ─────────────────────────────────────

    test("engineLoad with null stream falls back to env vars") {
      val (grpcCert, server, channel) = startFakeGrpcServer()
      try {
        val spi = FakeEnvHsmKeyStoreSpi(mapOf("HSM_PROXY_ENDPOINT" to "unused", "HSM_PROXY_KEY_ID" to "my-key"), channel)
        spi.engineLoad(null, null)
        spi.engineSize() shouldBe 1
        spi.engineContainsAlias("tls") shouldBe true
        spi.engineGetCertificate("tls") shouldBe grpcCert
      } finally {
        channel.shutdown()
        server.shutdown()
      }
    }

    test("engineLoad with empty stream falls back to env vars") {
      val (grpcCert, server, channel) = startFakeGrpcServer()
      try {
        val spi = FakeEnvHsmKeyStoreSpi(mapOf("HSM_PROXY_ENDPOINT" to "unused", "HSM_PROXY_KEY_ID" to "my-key"), channel)
        spi.engineLoad("".byteInputStream(), null)
        spi.engineSize() shouldBe 1
        spi.engineContainsAlias("tls") shouldBe true
        spi.engineGetCertificate("tls") shouldBe grpcCert
      } finally {
        channel.shutdown()
        server.shutdown()
      }
    }

    test("engineLoad throws KeyStoreException when stream is null and HSM_PROXY_ENDPOINT is missing") {
      val spi = FakeEnvHsmKeyStoreSpi(mapOf("HSM_PROXY_KEY_ID" to "my-key"), channel = null)
      shouldThrow<KeyStoreException> { spi.engineLoad(null, null) }
    }

    test("engineLoad throws KeyStoreException when stream is null and HSM_PROXY_KEY_ID is missing") {
      val (_, server, channel) = startFakeGrpcServer()
      try {
        val spi = FakeEnvHsmKeyStoreSpi(mapOf("HSM_PROXY_ENDPOINT" to "unused"), channel)
        shouldThrow<KeyStoreException> { spi.engineLoad(null, null) }
      } finally {
        channel.shutdown()
        server.shutdown()
      }
    }

    test("engineLoad env-var mode: engineGetKey returns HsmEcPrivateKey with correct keyId") {
      val (_, server, channel) = startFakeGrpcServer()
      try {
        val spi = FakeEnvHsmKeyStoreSpi(mapOf("HSM_PROXY_ENDPOINT" to "unused", "HSM_PROXY_KEY_ID" to "my-hsm-key"), channel)
        spi.engineLoad(null, null)
        val key = spi.engineGetKey("tls", null)
        key.shouldBeInstanceOf<HsmEcPrivateKey>()
        key.keyId shouldBe "my-hsm-key"
      } finally {
        channel.shutdown()
        server.shutdown()
      }
    }

    test("engineLoad supports multiple aliases") {
      val (cert2, file2) = TestCertificateFactory.generateSelfSignedEcCert()
      try {
        val cfg =
            """
            hsm.endpoint=localhost:50051
            keys.key-one.key_id=id-one
            keys.key-one.cert=${certFile.absolutePath}
            keys.key-two.key_id=id-two
            keys.key-two.cert=${file2.absolutePath}
            """
                .trimIndent()
        val spi = loadSpi(cfg)
        spi.engineSize() shouldBe 2
        spi.engineContainsAlias("key-one") shouldBe true
        spi.engineContainsAlias("key-two") shouldBe true
      } finally {
        file2.delete()
      }
    }

    // ── engineGetKey ──────────────────────────────────────────────────────

    test("engineGetKey returns HsmEcPrivateKey with correct keyId") {
      val spi = loadSpi(config(alias = "tls-key", keyId = "zeta-guard-tls-es256-v1"))
      val key = spi.engineGetKey("tls-key", null)
      key.shouldBeInstanceOf<HsmEcPrivateKey>()
      key.keyId shouldBe "zeta-guard-tls-es256-v1"
    }

    test("engineGetKey returns null for unknown alias") {
      val spi = loadSpi(config())
      spi.engineGetKey("no-such-alias", null).shouldBeNull()
    }

    test("engineGetKey returned key has EC algorithm") {
      val spi = loadSpi(config())
      val key = spi.engineGetKey("tls-key", null) as HsmEcPrivateKey
      key.getAlgorithm() shouldBe "EC"
    }

    test("engineGetKey returned key has no encoded material") {
      val spi = loadSpi(config())
      val key = spi.engineGetKey("tls-key", null) as HsmEcPrivateKey
      key.getEncoded().shouldBeNull()
    }

    // ── engineGetCertificate ──────────────────────────────────────────────

    test("engineGetCertificate returns the loaded X509Certificate") {
      val spi = loadSpi(config())
      val loaded = spi.engineGetCertificate("tls-key")
      loaded.shouldBeInstanceOf<X509Certificate>()
      loaded shouldBe cert
    }

    test("engineGetCertificate returns null for unknown alias") {
      val spi = loadSpi(config())
      spi.engineGetCertificate("unknown").shouldBeNull()
    }

    // ── engineGetCertificateChain ─────────────────────────────────────────

    test("engineGetCertificateChain returns single-element array") {
      val spi = loadSpi(config())
      val chain = spi.engineGetCertificateChain("tls-key")
      chain.shouldNotBeNull()
      chain.size shouldBe 1
      chain[0] shouldBe cert
    }

    test("engineGetCertificateChain returns null for unknown alias") {
      val spi = loadSpi(config())
      spi.engineGetCertificateChain("unknown").shouldBeNull()
    }

    // ── engineAliases / engineContainsAlias / engineSize ──────────────────

    test("engineAliases returns all configured aliases") {
      val (_, file2) = TestCertificateFactory.generateSelfSignedEcCert()
      try {
        val cfg =
            """
            hsm.endpoint=localhost:50051
            keys.alpha.key_id=id-alpha
            keys.alpha.cert=${certFile.absolutePath}
            keys.beta.key_id=id-beta
            keys.beta.cert=${file2.absolutePath}
            """
                .trimIndent()
        val aliases = loadSpi(cfg).engineAliases().toList()
        aliases shouldContainExactlyInAnyOrder listOf("alpha", "beta")
      } finally {
        file2.delete()
      }
    }

    test("engineContainsAlias returns true for known alias") { loadSpi(config()).engineContainsAlias("tls-key") shouldBe true }

    test("engineContainsAlias returns false for unknown alias") { loadSpi(config()).engineContainsAlias("ghost") shouldBe false }

    test("engineSize returns correct count") { loadSpi(config()).engineSize() shouldBe 1 }

    test("engineIsKeyEntry returns true for configured alias") { loadSpi(config()).engineIsKeyEntry("tls-key") shouldBe true }

    test("engineIsCertificateEntry always returns false") { loadSpi(config()).engineIsCertificateEntry("tls-key") shouldBe false }

    test("engineGetCreationDate returns cert notBefore date") {
      val spi = loadSpi(config())
      spi.engineGetCreationDate("tls-key") shouldBe cert.notBefore
    }

    // ── Write operations ──────────────────────────────────────────────────

    test("engineStore throws UnsupportedOperationException") {
      shouldThrow<UnsupportedOperationException> { loadSpi(config()).engineStore(null, null) }
    }

    test("engineSetKeyEntry throws UnsupportedOperationException") {
      shouldThrow<UnsupportedOperationException> {
        loadSpi(config()).engineSetKeyEntry("x", HsmEcPrivateKey("k", loadSpi(config()).grpcClient!!), null, null)
      }
    }

    test("engineDeleteEntry throws UnsupportedOperationException") {
      shouldThrow<UnsupportedOperationException> { loadSpi(config()).engineDeleteEntry("tls-key") }
    }

    test("engineSetCertificateEntry throws UnsupportedOperationException") {
      shouldThrow<UnsupportedOperationException> { loadSpi(config()).engineSetCertificateEntry("x", cert) }
    }
  }
}

// ── Test helpers ──────────────────────────────────────────────────────────────

/** [HsmKeyStoreSpi] that injects a pre-built in-process channel instead of connecting by name. */
private class FakeChannelHsmKeyStoreSpi(private val channel: ManagedChannel) : HsmKeyStoreSpi() {
  override fun buildGrpcClient(endpoint: String) = HsmProxyGrpcClient(channel)
}

/**
 * [HsmKeyStoreSpi] that overrides both env-var reading and the gRPC channel, for testing the env-var fallback path without real env vars or a real
 * gRPC endpoint.
 *
 * Pass [channel] as `null` to test error paths where the gRPC channel is never needed (e.g. endpoint env var missing → throws before channel
 * creation).
 */
private class FakeEnvHsmKeyStoreSpi(private val fakeEnv: Map<String, String>, private val channel: ManagedChannel?) : HsmKeyStoreSpi() {
  override fun readEnv(name: String): String? = fakeEnv[name]

  override fun buildGrpcClient(endpoint: String): HsmProxyGrpcClient =
      HsmProxyGrpcClient(channel ?: error("buildGrpcClient called but no channel was provided"))
}

data class FakeGrpcServer(val cert: X509Certificate, val server: Server, val channel: ManagedChannel)

/**
 * Starts an in-process gRPC server that responds to [GetCertificate] with a freshly generated self-signed cert, or with [error] if provided. The
 * caller is responsible for shutting down [FakeGrpcServer.server] and [FakeGrpcServer.channel].
 */
fun startFakeGrpcServer(error: StatusRuntimeException? = null): FakeGrpcServer {
  val (cert, certFile) = TestCertificateFactory.generateSelfSignedEcCert()
  val certPem = certFile.readText().also { certFile.delete() }
  val serverName = InProcessServerBuilder.generateName()
  val fakeService = FakeCertificateService(certPem = certPem, error = error)
  val server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeService).build().start()
  val channel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
  return FakeGrpcServer(cert, server, channel)
}

private class FakeCertificateService(private val certPem: String, private val error: StatusRuntimeException?) :
    HsmProxyServiceGrpc.HsmProxyServiceImplBase() {

  override fun getCertificate(request: GetCertificateRequest, responseObserver: StreamObserver<GetCertificateResponse>) {
    error?.let {
      responseObserver.onError(it)
      return
    }
    responseObserver.onNext(GetCertificateResponse.newBuilder().setCertificatePem(certPem).build())
    responseObserver.onCompleted()
  }

  override fun sign(request: SignRequest, responseObserver: StreamObserver<SignResponse>) {
    responseObserver.onNext(SignResponse.newBuilder().setSignature(ByteString.copyFrom(ByteArray(64))).build())
    responseObserver.onCompleted()
  }
}
