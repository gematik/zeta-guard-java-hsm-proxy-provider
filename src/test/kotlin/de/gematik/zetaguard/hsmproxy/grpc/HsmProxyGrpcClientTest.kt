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
package de.gematik.zetaguard.hsmproxy.grpc

import com.google.protobuf.ByteString
import de.gematik.zetaguard.hsmproxy.v1.DigestAlgorithm
import de.gematik.zetaguard.hsmproxy.v1.GetCertificateRequest
import de.gematik.zetaguard.hsmproxy.v1.GetCertificateResponse
import de.gematik.zetaguard.hsmproxy.v1.GetPublicKeyRequest
import de.gematik.zetaguard.hsmproxy.v1.GetPublicKeyResponse
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckRequest
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckResponse
import de.gematik.zetaguard.hsmproxy.v1.HsmProxyServiceGrpc
import de.gematik.zetaguard.hsmproxy.v1.SignRequest
import de.gematik.zetaguard.hsmproxy.v1.SignResponse
import io.grpc.Server
import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import io.grpc.stub.StreamObserver
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

class HsmProxyGrpcClientTest : FunSpec() {
  private val serverName = InProcessServerBuilder.generateName()
  private val mockService = FakeHsmProxyService()
  private lateinit var server: Server
  private lateinit var client: HsmProxyGrpcClient

  init {
    beforeSpec {
      server = InProcessServerBuilder.forName(serverName).directExecutor().addService(mockService).build().start()
      val channel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
      client = HsmProxyGrpcClient(channel)
    }

    afterSpec {
      if (::client.isInitialized) client.close()
      if (::server.isInitialized) server.shutdown()
    }

    // ── sign ──────────────────────────────────────────────────────────────

    test("sign returns P1363 signature bytes from proxy") {
      val expectedSignature = ByteArray(64) { it.toByte() } // 64 bytes = P-256 P1363
      mockService.signResponse = SignResponse.newBuilder().setSignature(ByteString.copyFrom(expectedSignature)).setKeyId("test-key").build()

      val result = client.sign("test-key", ByteArray(32))

      result shouldBe expectedSignature
    }

    test("sign sends key_id to proxy") {
      mockService.signResponse = SignResponse.newBuilder().setSignature(ByteString.copyFrom(ByteArray(64))).setKeyId("my-specific-key").build()

      client.sign("my-specific-key", ByteArray(32))

      mockService.lastSignRequest!!.keyId shouldBe "my-specific-key"
    }

    test("sign sends digest bytes unchanged to proxy") {
      val digest = ByteArray(32) { (it * 3).toByte() }
      mockService.signResponse = SignResponse.newBuilder().setSignature(ByteString.copyFrom(ByteArray(64))).setKeyId("k").build()

      client.sign("k", digest)

      mockService.lastSignRequest!!.data.toByteArray() shouldBe digest
    }

    test("sign always sets algorithm to NONE (pre-hashed digest)") {
      mockService.signResponse = SignResponse.newBuilder().setSignature(ByteString.copyFrom(ByteArray(64))).setKeyId("k").build()

      client.sign("k", ByteArray(32))

      mockService.lastSignRequest!!.algorithm shouldBe DigestAlgorithm.NONE
    }

    test("sign propagates gRPC NOT_FOUND as StatusRuntimeException") {
      mockService.signError = Status.NOT_FOUND.withDescription("key 'unknown' not found").asRuntimeException()

      val ex = shouldThrow<StatusRuntimeException> { client.sign("unknown", ByteArray(32)) }

      ex.status.code shouldBe Status.Code.NOT_FOUND
      ex.status.description shouldContain "unknown"
    }

    test("sign propagates gRPC UNAVAILABLE as StatusRuntimeException") {
      mockService.signError = Status.UNAVAILABLE.withDescription("HSM unreachable").asRuntimeException()

      val ex = shouldThrow<StatusRuntimeException> { client.sign("k", ByteArray(32)) }

      ex.status.code shouldBe Status.Code.UNAVAILABLE
    }

    // ── getPublicKey ──────────────────────────────────────────────────────

    test("getPublicKey returns full response from proxy") {
      val expectedPem = "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----"
      val expectedDer = ByteArray(91) { it.toByte() }
      val expectedJwk = """{"kty":"EC","crv":"P-256","x":"abc","y":"def"}"""
      mockService.publicKeyResponse =
          GetPublicKeyResponse.newBuilder()
              .setPublicKeyPem(expectedPem)
              .setPublicKeyDer(ByteString.copyFrom(expectedDer))
              .setJwkJson(expectedJwk)
              .build()

      val result = client.getPublicKey("tls-key")

      result.publicKeyPem shouldBe expectedPem
      result.publicKeyDer.toByteArray() shouldBe expectedDer
      result.jwkJson shouldBe expectedJwk
    }

    test("getPublicKey sends key_id to proxy") {
      mockService.publicKeyResponse = GetPublicKeyResponse.getDefaultInstance()

      client.getPublicKey("lookup-key")

      mockService.lastPublicKeyRequest!!.keyId shouldBe "lookup-key"
    }

    test("getPublicKey propagates gRPC NOT_FOUND as StatusRuntimeException") {
      mockService.publicKeyError = Status.NOT_FOUND.withDescription("key 'missing' not found").asRuntimeException()

      val ex = shouldThrow<StatusRuntimeException> { client.getPublicKey("missing") }

      ex.status.code shouldBe Status.Code.NOT_FOUND
    }

    // ── getCertificate ────────────────────────────────────────────────────

    test("getCertificate returns leaf PEM from proxy") {
      val expectedPem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
      mockService.certificateResponse = GetCertificateResponse.newBuilder().setCertificatePem(expectedPem).build()

      val result = client.getCertificate("tls-key.p256")

      result.certificatePem shouldBe expectedPem
    }

    test("getCertificate sends key_id to proxy") {
      mockService.certificateResponse = GetCertificateResponse.getDefaultInstance()

      client.getCertificate("my-cert-key.p256")

      mockService.lastCertificateRequest!!.keyId shouldBe "my-cert-key.p256"
    }

    test("getCertificate propagates gRPC NOT_FOUND as StatusRuntimeException") {
      mockService.certificateError = Status.NOT_FOUND.withDescription("key 'unknown' not found").asRuntimeException()

      val ex = shouldThrow<StatusRuntimeException> { client.getCertificate("unknown.p256") }

      ex.status.code shouldBe Status.Code.NOT_FOUND
    }

    // ── healthCheck ───────────────────────────────────────────────────────

    test("healthCheck returns SERVING status") {
      mockService.healthResponse =
          HealthCheckResponse.newBuilder().setStatus(HealthCheckResponse.ServingStatus.SERVING).setVersion("1.0.0").setHsmInfo("Test HSM").build()

      val result = client.healthCheck()

      result.status shouldBe HealthCheckResponse.ServingStatus.SERVING
      result.version shouldBe "1.0.0"
      result.hsmInfo shouldBe "Test HSM"
    }

    test("healthCheck returns NOT_SERVING when HSM is down") {
      mockService.healthResponse = HealthCheckResponse.newBuilder().setStatus(HealthCheckResponse.ServingStatus.NOT_SERVING).build()

      val result = client.healthCheck()

      result.status shouldBe HealthCheckResponse.ServingStatus.NOT_SERVING
    }

    test("healthCheck propagates gRPC UNAVAILABLE when proxy itself is unreachable") {
      mockService.healthError = Status.UNAVAILABLE.withDescription("proxy offline").asRuntimeException()

      val ex = shouldThrow<StatusRuntimeException> { client.healthCheck() }

      ex.status.code shouldBe Status.Code.UNAVAILABLE
    }
  }
}

// ── In-process fake gRPC service ─────────────────────────────────────────────

/**
 * Minimal fake [HsmProxyServiceGrpc.HsmProxyServiceImplBase] for unit tests.
 *
 * Set [signResponse] / [signError] before calling [HsmProxyGrpcClient.sign], and inspect [lastSignRequest] afterwards to verify what was sent. Same
 * pattern for the other RPCs.
 */
private class FakeHsmProxyService : HsmProxyServiceGrpc.HsmProxyServiceImplBase() {
  var signResponse: SignResponse? = null
  var signError: StatusRuntimeException? = null
  var lastSignRequest: SignRequest? = null

  var publicKeyResponse: GetPublicKeyResponse? = null
  var publicKeyError: StatusRuntimeException? = null
  var lastPublicKeyRequest: GetPublicKeyRequest? = null

  var certificateResponse: GetCertificateResponse? = null
  var certificateError: StatusRuntimeException? = null
  var lastCertificateRequest: GetCertificateRequest? = null

  var healthResponse: HealthCheckResponse? = null
  var healthError: StatusRuntimeException? = null

  override fun sign(request: SignRequest, responseObserver: StreamObserver<SignResponse>) {
    lastSignRequest = request
    signError?.let {
      responseObserver.onError(it)
      return
    }
    responseObserver.onNext(signResponse ?: SignResponse.getDefaultInstance())
    responseObserver.onCompleted()
  }

  override fun getPublicKey(request: GetPublicKeyRequest, responseObserver: StreamObserver<GetPublicKeyResponse>) {
    lastPublicKeyRequest = request
    publicKeyError?.let {
      responseObserver.onError(it)
      return
    }
    responseObserver.onNext(publicKeyResponse ?: GetPublicKeyResponse.getDefaultInstance())
    responseObserver.onCompleted()
  }

  override fun getCertificate(request: GetCertificateRequest, responseObserver: StreamObserver<GetCertificateResponse>) {
    lastCertificateRequest = request
    certificateError?.let {
      responseObserver.onError(it)
      return
    }
    responseObserver.onNext(certificateResponse ?: GetCertificateResponse.getDefaultInstance())
    responseObserver.onCompleted()
  }

  override fun healthCheck(request: HealthCheckRequest, responseObserver: StreamObserver<HealthCheckResponse>) {
    healthError?.let {
      responseObserver.onError(it)
      return
    }
    responseObserver.onNext(healthResponse ?: HealthCheckResponse.getDefaultInstance())
    responseObserver.onCompleted()
  }
}
