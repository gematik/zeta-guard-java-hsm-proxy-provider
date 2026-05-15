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
package de.gematik.zetaguard.hsmproxy.cipher

import com.google.protobuf.ByteString
import de.gematik.zetaguard.hsmproxy.HsmProxyProvider
import de.gematik.zetaguard.hsmproxy.grpc.HsmProxyGrpcClient
import de.gematik.zetaguard.hsmproxy.keystore.HsmSecretKey
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
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.security.InvalidKeyException
import java.security.Security
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class HsmAesGcmCipherSpiTest : FunSpec() {
  private val serverName = InProcessServerBuilder.generateName()
  private val fakeService = FakeEncryptDecryptService()
  private lateinit var server: Server
  private lateinit var client: HsmProxyGrpcClient

  init {
    beforeSpec {
      Security.addProvider(HsmProxyProvider())
      server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeService).build().start()
      val channel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
      client = HsmProxyGrpcClient(channel)
    }

    afterSpec {
      Security.removeProvider(HsmProxyProvider.NAME)
      if (::client.isInitialized) client.close()
      if (::server.isInitialized) server.shutdown()
    }

    beforeEach {
      fakeService.encryptResponse = null
      fakeService.encryptError = null
      fakeService.lastEncryptRequest = null
      fakeService.decryptResponse = null
      fakeService.decryptError = null
      fakeService.lastDecryptRequest = null
    }

    fun hsmKey(keyId: String = "kek-v1") = HsmSecretKey(keyId, client)

    // ── Encrypt ──────────────────────────────────────────────────────────

    test("encrypt returns ciphertext + tag from HSM Proxy") {
      val expectedCt = "encrypted-data".toByteArray()
      val expectedIv = ByteArray(12) { it.toByte() }
      val expectedTag = ByteArray(16) { (it + 50).toByte() }
      fakeService.encryptResponse =
          EncryptResponse.newBuilder()
              .setCiphertext(ByteString.copyFrom(expectedCt))
              .setIv(ByteString.copyFrom(expectedIv))
              .setTag(ByteString.copyFrom(expectedTag))
              .build()

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      val result = cipher.doFinal("hello".toByteArray())

      // Standard JCA GCM: doFinal returns ciphertext || tag
      result shouldBe expectedCt + expectedTag
      cipher.iv shouldBe expectedIv
    }

    test("encrypt sends plaintext and AAD to proxy") {
      fakeService.encryptResponse = EncryptResponse.getDefaultInstance()

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey("my-kek"))
      cipher.updateAAD("row-42".toByteArray())
      cipher.doFinal("secret".toByteArray())

      fakeService.lastEncryptRequest!!.keyId shouldBe "my-kek"
      fakeService.lastEncryptRequest!!.plaintext.toByteArray() shouldBe "secret".toByteArray()
      fakeService.lastEncryptRequest!!.associatedData.toByteArray() shouldBe "row-42".toByteArray()
    }

    test("encrypt with update accumulates plaintext") {
      fakeService.encryptResponse = EncryptResponse.getDefaultInstance()

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      cipher.update("hello ".toByteArray())
      cipher.doFinal("world".toByteArray())

      fakeService.lastEncryptRequest!!.plaintext.toByteArray() shouldBe "hello world".toByteArray()
    }

    test("encrypt throws BadPaddingException on gRPC failure") {
      fakeService.encryptError = Status.INTERNAL.withDescription("HSM error").asRuntimeException()

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())

      shouldThrow<BadPaddingException> { cipher.doFinal("data".toByteArray()) }
    }

    // ── Decrypt ──────────────────────────────────────────────────────────

    test("decrypt returns plaintext from HSM Proxy") {
      val expected = "decrypted-data".toByteArray()
      fakeService.decryptResponse = DecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(expected)).build()

      // Input must be ciphertext || tag (16 bytes tag at the end)
      val ciphertextWithTag = ByteArray(32) + ByteArray(16)

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.DECRYPT_MODE, hsmKey(), GCMParameterSpec(128, ByteArray(12)))
      val result = cipher.doFinal(ciphertextWithTag)

      result shouldBe expected
    }

    test("decrypt splits ciphertext and tag before sending to proxy") {
      fakeService.decryptResponse = DecryptResponse.getDefaultInstance()
      val iv = ByteArray(12) { (it + 10).toByte() }
      val ct = ByteArray(20) { it.toByte() }
      val tag = ByteArray(16) { (it + 100).toByte() }

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.DECRYPT_MODE, hsmKey("my-kek"), GCMParameterSpec(128, iv))
      cipher.updateAAD("row-42".toByteArray())
      cipher.doFinal(ct + tag) // combined: ciphertext || tag

      fakeService.lastDecryptRequest!!.keyId shouldBe "my-kek"
      fakeService.lastDecryptRequest!!.ciphertext.toByteArray() shouldBe ct
      fakeService.lastDecryptRequest!!.tag.toByteArray() shouldBe tag
      fakeService.lastDecryptRequest!!.iv.toByteArray() shouldBe iv
      fakeService.lastDecryptRequest!!.associatedData.toByteArray() shouldBe "row-42".toByteArray()
    }

    test("decrypt throws BadPaddingException on GCM auth failure") {
      fakeService.decryptError = Status.INVALID_ARGUMENT.withDescription("GCM auth tag mismatch").asRuntimeException()

      val ciphertextWithTag = ByteArray(32) + ByteArray(16)
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.DECRYPT_MODE, hsmKey(), GCMParameterSpec(128, ByteArray(12)))

      shouldThrow<BadPaddingException> { cipher.doFinal(ciphertextWithTag) }
    }

    test("decrypt throws BadPaddingException when input is too short for tag") {
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.DECRYPT_MODE, hsmKey(), GCMParameterSpec(128, ByteArray(12)))

      shouldThrow<BadPaddingException> { cipher.doFinal(ByteArray(10)) } // less than 16 bytes
    }

    // ── Key validation ───────────────────────────────────────────────────

    test("init rejects non-HsmSecretKey") {
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      val regularKey = SecretKeySpec(ByteArray(32), "AES")

      shouldThrow<InvalidKeyException> { cipher.init(Cipher.ENCRYPT_MODE, regularKey) }
    }

    // ── Query methods ────────────────────────────────────────────────────

    test("getIV returns null before encrypt") {
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      cipher.iv.shouldBeNull()
    }

    test("getIV returns server-generated IV after encrypt") {
      val expectedIv = ByteArray(12) { (it + 1).toByte() }
      fakeService.encryptResponse = EncryptResponse.newBuilder().setIv(ByteString.copyFrom(expectedIv)).build()

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      cipher.doFinal("data".toByteArray())

      cipher.iv.shouldNotBeNull()
      cipher.iv shouldBe expectedIv
    }

    test("getBlockSize returns 16") {
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      cipher.blockSize shouldBe 16
    }

    // ── Mode / padding rejection ─────────────────────────────────────────
    // engineSetMode/engineSetPadding are normally invoked by JCA only when a partial
    // transformation matches (e.g. "AES" registered + "AES/CBC/..." requested). Since the
    // provider registers the full transformation "AES/GCM/NoPadding", JCA never calls them
    // — exercise them directly via reflection.

    test("engineSetMode accepts GCM (case-insensitive)") {
      invokeProtected(HsmAesGcmCipherSpi(), "engineSetMode", "gcm") // must not throw
    }

    test("engineSetMode rejects non-GCM mode") {
      shouldThrow<UnsupportedOperationException> { invokeProtected(HsmAesGcmCipherSpi(), "engineSetMode", "CBC") }
    }

    test("engineSetPadding accepts NoPadding (case-insensitive)") {
      invokeProtected(HsmAesGcmCipherSpi(), "engineSetPadding", "nopadding") // must not throw
    }

    test("engineSetPadding rejects non-NoPadding") {
      shouldThrow<UnsupportedOperationException> { invokeProtected(HsmAesGcmCipherSpi(), "engineSetPadding", "PKCS5Padding") }
    }

    // ── engineGetParameters ──────────────────────────────────────────────

    test("getParameters returns null before encrypt") {
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      cipher.parameters.shouldBeNull()
    }

    test("getParameters returns AlgorithmParameters with IV after encrypt") {
      val expectedIv = ByteArray(12) { (it + 7).toByte() }
      fakeService.encryptResponse = EncryptResponse.newBuilder().setIv(ByteString.copyFrom(expectedIv)).build()

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      cipher.doFinal("data".toByteArray())

      val params = cipher.parameters.shouldNotBeNull()
      params.getParameterSpec(GCMParameterSpec::class.java).iv shouldBe expectedIv
    }

    // ── init via AlgorithmParameters ─────────────────────────────────────

    test("init accepts IV via AlgorithmParameters (decrypt path)") {
      val iv = ByteArray(12) { (it + 3).toByte() }
      val params = java.security.AlgorithmParameters.getInstance("GCM").apply { init(GCMParameterSpec(128, iv)) }

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.DECRYPT_MODE, hsmKey(), params)

      cipher.iv shouldBe iv
    }

    test("init rejects non-GCMParameterSpec") {
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      shouldThrow<java.security.InvalidAlgorithmParameterException> {
        cipher.init(Cipher.DECRYPT_MODE, hsmKey(), javax.crypto.spec.IvParameterSpec(ByteArray(12)))
      }
    }

    // ── decrypt without IV ───────────────────────────────────────────────

    test("decrypt without GCMParameterSpec throws IllegalStateException") {
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.DECRYPT_MODE, hsmKey()) // no params → iv null

      shouldThrow<IllegalStateException> { cipher.doFinal(ByteArray(32)) }
    }

    // ── output-array overloads ───────────────────────────────────────────

    test("doFinal with output array writes ciphertext+tag and returns size") {
      val expectedCt = "encrypted".toByteArray()
      val expectedTag = ByteArray(16) { (it + 1).toByte() }
      fakeService.encryptResponse =
          EncryptResponse.newBuilder().setCiphertext(ByteString.copyFrom(expectedCt)).setTag(ByteString.copyFrom(expectedTag)).build()

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      val output = ByteArray(64)
      val written = cipher.doFinal(ByteArray(0), 0, 0, output, 0)

      written shouldBe (expectedCt.size + expectedTag.size)
      output.copyOfRange(0, written) shouldBe (expectedCt + expectedTag)
    }

    test("update with output array buffers input and returns 0") {
      fakeService.encryptResponse = EncryptResponse.getDefaultInstance()

      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      val written = cipher.update("buffered".toByteArray(), 0, 8, ByteArray(64), 0)
      cipher.doFinal()

      written shouldBe 0
      fakeService.lastEncryptRequest!!.plaintext.toByteArray() shouldBe "buffered".toByteArray()
    }

    // ── engineGetOutputSize ──────────────────────────────────────────────

    test("getOutputSize returns inputLen + 16 (GCM tag overhead)") {
      val cipher = Cipher.getInstance(HsmProxyProvider.CIPHER_ALGORITHM, HsmProxyProvider.NAME)
      cipher.init(Cipher.ENCRYPT_MODE, hsmKey())
      cipher.getOutputSize(100) shouldBe 116
    }
  }
}

/**
 * Invokes a protected method on [target] by name, unwrapping any [java.lang.reflect.InvocationTargetException]. Used to test SPI methods that JCA
 * does not call when the provider registers a full transformation (e.g. `engineSetMode` is bypassed because `Cipher.AES/GCM/NoPadding` is registered
 * in full).
 */
private fun invokeProtected(target: Any, methodName: String, vararg args: Any?): Any? {
  val method = target.javaClass.declaredMethods.first { it.name == methodName && it.parameterCount == args.size }
  method.isAccessible = true
  return try {
    method.invoke(target, *args)
  } catch (e: java.lang.reflect.InvocationTargetException) {
    throw e.cause ?: e
  }
}

// ── Fake gRPC service ────────────────────────────────────────────────────────

private class FakeEncryptDecryptService : HsmProxyServiceGrpc.HsmProxyServiceImplBase() {
  var encryptResponse: EncryptResponse? = null
  var encryptError: io.grpc.StatusRuntimeException? = null
  var lastEncryptRequest: EncryptRequest? = null

  var decryptResponse: DecryptResponse? = null
  var decryptError: io.grpc.StatusRuntimeException? = null
  var lastDecryptRequest: DecryptRequest? = null

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
}
