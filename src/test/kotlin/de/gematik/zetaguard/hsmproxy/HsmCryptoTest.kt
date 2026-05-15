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

import com.google.protobuf.ByteString
import de.gematik.zetaguard.hsmproxy.grpc.HsmProxyGrpcClient
import de.gematik.zetaguard.hsmproxy.v1.DecryptRequest
import de.gematik.zetaguard.hsmproxy.v1.DecryptResponse
import de.gematik.zetaguard.hsmproxy.v1.EncryptRequest
import de.gematik.zetaguard.hsmproxy.v1.EncryptResponse
import de.gematik.zetaguard.hsmproxy.v1.HsmProxyServiceGrpc
import io.grpc.Server
import io.grpc.Status
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import io.grpc.stub.StreamObserver
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

class HsmCryptoTest : FunSpec() {
  private val serverName = InProcessServerBuilder.generateName()
  private val fakeService = FakeEncryptDecryptService()
  private lateinit var server: Server
  private lateinit var crypto: HsmCrypto

  init {
    beforeSpec {
      server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeService).build().start()
      val channel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
      crypto = HsmCrypto(HsmProxyGrpcClient(channel))
    }

    afterSpec {
      if (::crypto.isInitialized) crypto.close()
      if (::server.isInitialized) server.shutdown()
    }

    beforeEach { fakeService.reset() }

    // ── encrypt ──────────────────────────────────────────────────────────

    test("encrypt returns iv || ciphertext || tag") {
      val iv = ByteArray(12) { (it + 1).toByte() }
      val ct = "encrypted-data".toByteArray()
      val tag = ByteArray(16) { (it + 50).toByte() }
      fakeService.encryptResponse =
          EncryptResponse.newBuilder().setIv(ByteString.copyFrom(iv)).setCiphertext(ByteString.copyFrom(ct)).setTag(ByteString.copyFrom(tag)).build()

      val result = crypto.encrypt("plaintext".toByteArray(), keyId = "kek-v1")

      result shouldBe iv + ct + tag
    }

    test("encrypt sends keyId and plaintext to HSM Proxy") {
      fakeService.encryptResponse =
          EncryptResponse.newBuilder().setIv(ByteString.copyFrom(ByteArray(12))).setTag(ByteString.copyFrom(ByteArray(16))).build()

      crypto.encrypt("my-data".toByteArray(), keyId = "my-key")

      fakeService.lastEncryptRequest!!.keyId shouldBe "my-key"
      fakeService.lastEncryptRequest!!.plaintext.toByteArray() shouldBe "my-data".toByteArray()
    }

    test("encrypt passes AAD to HSM Proxy") {
      fakeService.encryptResponse =
          EncryptResponse.newBuilder().setIv(ByteString.copyFrom(ByteArray(12))).setTag(ByteString.copyFrom(ByteArray(16))).build()

      crypto.encrypt("data".toByteArray(), aad = "row-42".toByteArray(), keyId = "kek-v1")

      fakeService.lastEncryptRequest!!.associatedData.toByteArray() shouldBe "row-42".toByteArray()
    }

    // ── decrypt ──────────────────────────────────────────────────────────

    test("decrypt splits iv, ciphertext, and tag correctly") {
      val iv = ByteArray(12) { (it + 1).toByte() }
      val ct = "encrypted-data".toByteArray()
      val tag = ByteArray(16) { (it + 50).toByte() }
      val blob = iv + ct + tag

      fakeService.decryptResponse = DecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom("original".toByteArray())).build()

      val result = crypto.decrypt(blob, keyId = "kek-v1")

      result shouldBe "original".toByteArray()
      fakeService.lastDecryptRequest!!.iv.toByteArray() shouldBe iv
      fakeService.lastDecryptRequest!!.ciphertext.toByteArray() shouldBe ct
      fakeService.lastDecryptRequest!!.tag.toByteArray() shouldBe tag
    }

    test("decrypt passes AAD to HSM Proxy") {
      val blob = ByteArray(12 + 10 + 16)
      fakeService.decryptResponse = DecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(ByteArray(0))).build()

      crypto.decrypt(blob, aad = "row-42".toByteArray(), keyId = "kek-v1")

      fakeService.lastDecryptRequest!!.associatedData.toByteArray() shouldBe "row-42".toByteArray()
    }

    test("decrypt rejects blob shorter than iv + tag") {
      val tooShort = ByteArray(12 + 16) // exactly iv + tag, no ciphertext

      val ex = shouldThrow<IllegalArgumentException> { crypto.decrypt(tooShort, keyId = "kek-v1") }
      ex.message shouldContain "too short"
    }

    // ── round-trip ───────────────────────────────────────────────────────

    test("encrypt then decrypt round-trips through the blob format") {
      val plaintext = "secret DEK".toByteArray()
      val iv = ByteArray(12) { 0x0A }
      val ct = "cipherdata".toByteArray()
      val tag = ByteArray(16) { 0x0B }

      fakeService.encryptResponse =
          EncryptResponse.newBuilder().setIv(ByteString.copyFrom(iv)).setCiphertext(ByteString.copyFrom(ct)).setTag(ByteString.copyFrom(tag)).build()
      fakeService.decryptResponse = DecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(plaintext)).build()

      val encrypted = crypto.encrypt(plaintext, keyId = "kek-v1")
      val decrypted = crypto.decrypt(encrypted, keyId = "kek-v1")

      decrypted shouldBe plaintext
    }

    // ── companion / env-var defaults ─────────────────────────────────────

    test("defaultKekId throws when HSM_PROXY_KEK_ID is not set") {
      val ex = shouldThrow<IllegalStateException> { HsmCrypto.defaultKekId() }
      ex.message shouldContain HsmCrypto.ENV_KEK_ID
    }

    test("defaultKekId returns value when HSM_PROXY_KEK_ID is set") {
      HsmCrypto.getenv = { name -> if (name == HsmCrypto.ENV_KEK_ID) "test-kek" else null }
      try {
        HsmCrypto.defaultKekId() shouldBe "test-kek"
      } finally {
        HsmCrypto.reset()
      }
    }

    test("static encrypt uses env-var defaults for endpoint and keyId") {
      HsmCrypto.reset()
      // Inject an in-process-backed instance directly — avoids DNS resolution of the server name.
      val inProcessChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
      HsmCrypto.defaultInstance = HsmCrypto(HsmProxyGrpcClient(inProcessChannel))
      HsmCrypto.getenv = { name -> if (name == HsmCrypto.ENV_KEK_ID) "env-kek" else null }
      try {
        fakeService.encryptResponse =
            EncryptResponse.newBuilder().setIv(ByteString.copyFrom(ByteArray(12))).setTag(ByteString.copyFrom(ByteArray(16))).build()

        HsmCrypto.encrypt("data".toByteArray())

        fakeService.lastEncryptRequest!!.keyId shouldBe "env-kek"
      } finally {
        HsmCrypto.reset()
      }
    }

    test("static decrypt uses env-var defaults for endpoint and keyId") {
      HsmCrypto.reset()
      val inProcessChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
      HsmCrypto.defaultInstance = HsmCrypto(HsmProxyGrpcClient(inProcessChannel))
      HsmCrypto.getenv = { name -> if (name == HsmCrypto.ENV_KEK_ID) "env-kek" else null }
      try {
        fakeService.decryptResponse = DecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom("ok".toByteArray())).build()

        val result = HsmCrypto.decrypt(ByteArray(12 + 1 + 16))

        fakeService.lastDecryptRequest!!.keyId shouldBe "env-kek"
        result shouldBe "ok".toByteArray()
      } finally {
        HsmCrypto.reset()
      }
    }

    test("static encrypt throws when HSM_PROXY_ENDPOINT is not set") {
      HsmCrypto.reset()
      shouldThrow<IllegalStateException> { HsmCrypto.encrypt("data".toByteArray(), keyId = "kek") }
    }

    test("static decrypt throws when HSM_PROXY_ENDPOINT is not set") {
      HsmCrypto.reset()
      shouldThrow<IllegalStateException> { HsmCrypto.decrypt(ByteArray(12 + 1 + 16), keyId = "kek") }
    }

    test("constructor with endpoint creates a usable instance") {
      val instance = HsmCrypto(HsmProxyGrpcClient(InProcessChannelBuilder.forName(serverName).directExecutor().build()))
      fakeService.encryptResponse =
          EncryptResponse.newBuilder().setIv(ByteString.copyFrom(ByteArray(12))).setTag(ByteString.copyFrom(ByteArray(16))).build()
      val result = instance.encrypt("test".toByteArray(), keyId = "k")
      result.size shouldBe (12 + 0 + 16)
      instance.close()
    }
  }
}

// ── Fake gRPC service ────────────────────────────────────────────────────────

private class FakeEncryptDecryptService : HsmProxyServiceGrpc.HsmProxyServiceImplBase() {
  var encryptResponse: EncryptResponse? = null
  var decryptResponse: DecryptResponse? = null
  var lastEncryptRequest: EncryptRequest? = null
  var lastDecryptRequest: DecryptRequest? = null

  fun reset() {
    encryptResponse = null
    decryptResponse = null
    lastEncryptRequest = null
    lastDecryptRequest = null
  }

  override fun encrypt(request: EncryptRequest, responseObserver: StreamObserver<EncryptResponse>) {
    lastEncryptRequest = request
    val response =
        encryptResponse
            ?: run {
              responseObserver.onError(Status.UNIMPLEMENTED.asRuntimeException())
              return
            }
    responseObserver.onNext(response)
    responseObserver.onCompleted()
  }

  override fun decrypt(request: DecryptRequest, responseObserver: StreamObserver<DecryptResponse>) {
    lastDecryptRequest = request
    val response =
        decryptResponse
            ?: run {
              responseObserver.onError(Status.UNIMPLEMENTED.asRuntimeException())
              return
            }
    responseObserver.onNext(response)
    responseObserver.onCompleted()
  }
}
