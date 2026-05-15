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
import de.gematik.zetaguard.hsmproxy.v1.DecryptRequest
import de.gematik.zetaguard.hsmproxy.v1.DecryptResponse
import de.gematik.zetaguard.hsmproxy.v1.DigestAlgorithm
import de.gematik.zetaguard.hsmproxy.v1.EncryptRequest
import de.gematik.zetaguard.hsmproxy.v1.EncryptResponse
import de.gematik.zetaguard.hsmproxy.v1.GetCertificateRequest
import de.gematik.zetaguard.hsmproxy.v1.GetCertificateResponse
import de.gematik.zetaguard.hsmproxy.v1.GetPublicKeyRequest
import de.gematik.zetaguard.hsmproxy.v1.GetPublicKeyResponse
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckRequest
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckResponse
import de.gematik.zetaguard.hsmproxy.v1.HsmProxyServiceGrpc
import de.gematik.zetaguard.hsmproxy.v1.SignRequest
import de.gematik.zetaguard.hsmproxy.v1.SignResponse
import de.gematik.zetaguard.hsmproxy.v1.SymmetricEncryptionAlgorithm
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

    // ── encrypt ──────────────────────────────────────────────────────────

    test("encrypt returns ciphertext, IV, and tag from proxy") {
      val ct = ByteArray(32) { it.toByte() }
      val iv = ByteArray(12) { (it + 100).toByte() }
      val tag = ByteArray(16) { (it + 200).toByte() }
      mockService.encryptResponse =
          EncryptResponse.newBuilder().setCiphertext(ByteString.copyFrom(ct)).setIv(ByteString.copyFrom(iv)).setTag(ByteString.copyFrom(tag)).build()

      val result = client.encrypt("kek-v1", "hello".toByteArray())

      result.ciphertext.toByteArray() shouldBe ct
      result.iv.toByteArray() shouldBe iv
      result.tag.toByteArray() shouldBe tag
    }

    test("encrypt sends key_id, plaintext, algorithm, and AAD to proxy") {
      mockService.encryptResponse = EncryptResponse.getDefaultInstance()
      val plaintext = "secret-dek".toByteArray()
      val aad = "row-42".toByteArray()

      client.encrypt("kek-v1", plaintext, aad)

      mockService.lastEncryptRequest!!.keyId shouldBe "kek-v1"
      mockService.lastEncryptRequest!!.plaintext.toByteArray() shouldBe plaintext
      mockService.lastEncryptRequest!!.algorithm shouldBe SymmetricEncryptionAlgorithm.AES_256_GCM
      mockService.lastEncryptRequest!!.associatedData.toByteArray() shouldBe aad
    }

    test("encrypt sends empty AAD when not specified") {
      mockService.encryptResponse = EncryptResponse.getDefaultInstance()

      client.encrypt("kek-v1", "data".toByteArray())

      mockService.lastEncryptRequest!!.associatedData.toByteArray() shouldBe ByteArray(0)
    }

    test("encrypt propagates gRPC NOT_FOUND as StatusRuntimeException") {
      mockService.encryptError = Status.NOT_FOUND.withDescription("key 'unknown' not found").asRuntimeException()

      val ex = shouldThrow<StatusRuntimeException> { client.encrypt("unknown", ByteArray(32)) }

      ex.status.code shouldBe Status.Code.NOT_FOUND
    }

    // ── decrypt ──────────────────────────────────────────────────────────

    test("decrypt returns plaintext from proxy") {
      val expected = "decrypted-dek".toByteArray()
      mockService.decryptResponse = DecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(expected)).build()

      val result = client.decrypt("kek-v1", ByteArray(32), ByteArray(12), ByteArray(16))

      result.plaintext.toByteArray() shouldBe expected
    }

    test("decrypt sends all fields to proxy") {
      mockService.decryptResponse = DecryptResponse.getDefaultInstance()
      val ct = ByteArray(32) { it.toByte() }
      val iv = ByteArray(12) { (it + 1).toByte() }
      val tag = ByteArray(16) { (it + 2).toByte() }
      val aad = "row-99".toByteArray()

      client.decrypt("kek-v1", ct, iv, tag, aad)

      mockService.lastDecryptRequest!!.keyId shouldBe "kek-v1"
      mockService.lastDecryptRequest!!.ciphertext.toByteArray() shouldBe ct
      mockService.lastDecryptRequest!!.iv.toByteArray() shouldBe iv
      mockService.lastDecryptRequest!!.tag.toByteArray() shouldBe tag
      mockService.lastDecryptRequest!!.algorithm shouldBe SymmetricEncryptionAlgorithm.AES_256_GCM
      mockService.lastDecryptRequest!!.associatedData.toByteArray() shouldBe aad
    }

    test("decrypt propagates gRPC INVALID_ARGUMENT on tampered ciphertext") {
      mockService.decryptError = Status.INVALID_ARGUMENT.withDescription("GCM authentication failed").asRuntimeException()

      val ex = shouldThrow<StatusRuntimeException> { client.decrypt("kek-v1", ByteArray(32), ByteArray(12), ByteArray(16)) }

      ex.status.code shouldBe Status.Code.INVALID_ARGUMENT
      ex.status.description shouldContain "authentication failed"
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

  var encryptResponse: EncryptResponse? = null
  var encryptError: StatusRuntimeException? = null
  var lastEncryptRequest: EncryptRequest? = null

  var decryptResponse: DecryptResponse? = null
  var decryptError: StatusRuntimeException? = null
  var lastDecryptRequest: DecryptRequest? = null

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

  override fun encrypt(request: EncryptRequest, responseObserver: StreamObserver<EncryptResponse>) {
    lastEncryptRequest = request
    encryptError?.let {
      responseObserver.onError(it)
      return
    }
    responseObserver.onNext(encryptResponse ?: EncryptResponse.getDefaultInstance())
    responseObserver.onCompleted()
  }

  override fun decrypt(request: DecryptRequest, responseObserver: StreamObserver<DecryptResponse>) {
    lastDecryptRequest = request
    decryptError?.let {
      responseObserver.onError(it)
      return
    }
    responseObserver.onNext(decryptResponse ?: DecryptResponse.getDefaultInstance())
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
