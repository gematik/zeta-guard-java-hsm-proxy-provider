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
package de.gematik.zetaguard.hsmproxy.signature

import com.google.protobuf.ByteString
import de.gematik.zetaguard.hsmproxy.HsmProxyProvider
import de.gematik.zetaguard.hsmproxy.grpc.HsmProxyGrpcClient
import de.gematik.zetaguard.hsmproxy.keystore.HsmEcPrivateKey
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
import io.mockk.mockk
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.Signature
import java.security.SignatureException

class HsmEcdsaSignatureSpiTest : FunSpec() {
  private val provider = HsmProxyProvider()
  private val serverName = InProcessServerBuilder.generateName()
  private val fakeService = FakeSignService()
  private lateinit var server: Server
  private lateinit var client: HsmProxyGrpcClient
  private lateinit var hsmKey: HsmEcPrivateKey

  init {
    beforeSpec {
      server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeService).build().start()
      val channel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
      client = HsmProxyGrpcClient(channel)
      hsmKey = HsmEcPrivateKey("test-key-id", mockk(), client)
    }

    afterSpec {
      if (::client.isInitialized) client.close()
      if (::server.isInitialized) server.shutdown()
    }

    // ── initSign ──────────────────────────────────────────────────────────

    test("initSign accepts HsmEcPrivateKey") {
      val sig = Signature.getInstance("SHA256withECDSA", provider)
      sig.initSign(hsmKey) // must not throw
    }

    test("initSign rejects non-HsmEcPrivateKey") {
      val sig = Signature.getInstance("SHA256withECDSA", provider)
      val otherKey =
          object : java.security.PrivateKey {
            override fun getAlgorithm() = "RSA"

            override fun getEncoded() = null

            override fun getFormat() = null
          }
      shouldThrow<InvalidKeyException> { sig.initSign(otherKey) }
    }

    // ── initVerify / verify / parameter API ───────────────────────────────

    test("initVerify throws UnsupportedOperationException") {
      val sig = Signature.getInstance("SHA256withECDSA", provider)
      shouldThrow<UnsupportedOperationException> { sig.initVerify(null as java.security.PublicKey?) }
    }

    test("engineVerify throws UnsupportedOperationException") {
      shouldThrow<UnsupportedOperationException> { invokeProtected(HsmEcdsaSignatureSpi(), "engineVerify", ByteArray(64)) }
    }

    test("engineSetParameter throws UnsupportedOperationException") {
      shouldThrow<UnsupportedOperationException> { invokeProtected(HsmEcdsaSignatureSpi(), "engineSetParameter", "x", 1) }
    }

    test("engineGetParameter throws UnsupportedOperationException") {
      shouldThrow<UnsupportedOperationException> { invokeProtected(HsmEcdsaSignatureSpi(), "engineGetParameter", "x") }
    }

    // ── sign ──────────────────────────────────────────────────────────────

    test("sign throws SignatureException when not initialised") {
      val sig = Signature.getInstance("SHA256withECDSA", provider)
      shouldThrow<SignatureException> { sig.sign() }
    }

    test("sign sends SHA-256 hash of data to proxy") {
      fakeService.nextSignature = ByteArray(64)

      val data = "hello hsm".toByteArray()
      val expectedDigest = MessageDigest.getInstance("SHA-256").digest(data)

      val sig = Signature.getInstance("SHA256withECDSA", provider)
      sig.initSign(hsmKey)
      sig.update(data)
      sig.sign()

      fakeService.lastRequest!!.data.toByteArray() shouldBe expectedDigest
    }

    test("sign sends key_id to proxy") {
      fakeService.nextSignature = ByteArray(64)
      val keyWithId = HsmEcPrivateKey("my-special-key", mockk(), client)

      val sig = Signature.getInstance("SHA256withECDSA", provider)
      sig.initSign(keyWithId)
      sig.sign()

      fakeService.lastRequest!!.keyId shouldBe "my-special-key"
    }

    test("sign returns DER-encoded signature") {
      // r = 1, s = 2 padded to 32 bytes each
      val p1363 = ByteArray(64)
      p1363[31] = 0x01
      p1363[63] = 0x02
      fakeService.nextSignature = p1363

      val sig = Signature.getInstance("SHA256withECDSA", provider)
      sig.initSign(hsmKey)
      val der = sig.sign()

      // Expected: SEQUENCE { INTEGER 1, INTEGER 2 } = 30 06 02 01 01 02 01 02
      der shouldBe byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)
    }

    test("sign accumulates data from multiple update(byte) calls") {
      fakeService.nextSignature = ByteArray(64)
      val data = byteArrayOf(0x01, 0x02, 0x03)
      val expectedDigest = MessageDigest.getInstance("SHA-256").digest(data)

      val sig = Signature.getInstance("SHA256withECDSA", provider)
      sig.initSign(hsmKey)
      data.forEach { sig.update(it) }
      sig.sign()

      fakeService.lastRequest!!.data.toByteArray() shouldBe expectedDigest
    }

    test("sign accumulates data across multiple update(array) calls") {
      fakeService.nextSignature = ByteArray(64)
      val chunk1 = "hello".toByteArray()
      val chunk2 = " world".toByteArray()
      val expectedDigest = MessageDigest.getInstance("SHA-256").digest(chunk1 + chunk2)

      val sig = Signature.getInstance("SHA256withECDSA", provider)
      sig.initSign(hsmKey)
      sig.update(chunk1)
      sig.update(chunk2)
      sig.sign()

      fakeService.lastRequest!!.data.toByteArray() shouldBe expectedDigest
    }

    test("sign resets buffer after re-initSign") {
      fakeService.nextSignature = ByteArray(64)

      val sig = Signature.getInstance("SHA256withECDSA", provider)

      // First sign — "first"
      sig.initSign(hsmKey)
      sig.update("first".toByteArray())
      sig.sign()

      // Re-init and sign with different data — buffer must be clean
      val secondData = "second".toByteArray()
      sig.initSign(hsmKey)
      sig.update(secondData)
      sig.sign()

      val expectedDigest = MessageDigest.getInstance("SHA-256").digest(secondData)
      fakeService.lastRequest!!.data.toByteArray() shouldBe expectedDigest
    }

    test("sign wraps gRPC error in SignatureException") {
      fakeService.signError = Status.UNAVAILABLE.withDescription("HSM proxy down").asRuntimeException()

      val sig = Signature.getInstance("SHA256withECDSA", provider)
      sig.initSign(hsmKey)

      val ex = shouldThrow<SignatureException> { sig.sign() }
      ex.message shouldContain "HSM Proxy signing failed"

      fakeService.signError = null // reset for subsequent tests
    }

    // ── p1363ToDer (internal — callable directly) ─────────────────────────

    test("p1363ToDer rejects payload != 64 bytes") {
      val spi = HsmEcdsaSignatureSpi()
      shouldThrow<SignatureException> { spi.p1363ToDer(ByteArray(63)) }
      shouldThrow<SignatureException> { spi.p1363ToDer(ByteArray(65)) }
    }

    test("p1363ToDer adds leading zero when r high bit is set") {
      val p1363 = ByteArray(64)
      p1363[0] = 0x80.toByte() // r high bit set → BigInteger.toByteArray() prepends 0x00
      p1363[32] = 0x01 // s first byte 0x01 (no high-bit issue)
      p1363[63] = 0x01

      val der = HsmEcdsaSignatureSpi().p1363ToDer(p1363)

      // DER: 0x30 <seqLen> 0x02 <rLen=33> 0x00 0x80 ...
      (der[2].toInt() and 0xFF) shouldBe 0x02 // r INTEGER tag
      (der[3].toInt() and 0xFF) shouldBe 33 // r length = 32 value bytes + 1 leading 0x00
      (der[4].toInt() and 0xFF) shouldBe 0x00 // leading zero
    }

    test("p1363ToDer produces valid SEQUENCE structure") {
      val p1363 = ByteArray(64) { (it + 1).toByte() }
      val der = HsmEcdsaSignatureSpi().p1363ToDer(p1363)

      (der[0].toInt() and 0xFF) shouldBe 0x30 // SEQUENCE tag
      (der[2].toInt() and 0xFF) shouldBe 0x02 // first INTEGER tag
    }
  }
}

/**
 * Invokes a protected method on [target] by name, unwrapping any [java.lang.reflect.InvocationTargetException]. Used to test SPI methods that JCA
 * guards behind state checks (e.g. `Signature.verify` short-circuits on un-initialised state before reaching `engineVerify`).
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

// ── In-process fake gRPC service ─────────────────────────────────────────────

private class FakeSignService : HsmProxyServiceGrpc.HsmProxyServiceImplBase() {
  var nextSignature: ByteArray = ByteArray(64)
  var signError: StatusRuntimeException? = null
  var lastRequest: SignRequest? = null

  override fun sign(request: SignRequest, responseObserver: StreamObserver<SignResponse>) {
    lastRequest = request
    signError?.let {
      responseObserver.onError(it)
      return
    }
    responseObserver.onNext(SignResponse.newBuilder().setSignature(ByteString.copyFrom(nextSignature)).setKeyId(request.keyId).build())
    responseObserver.onCompleted()
  }

  override fun getPublicKey(request: GetPublicKeyRequest, responseObserver: StreamObserver<GetPublicKeyResponse>) {
    responseObserver.onNext(GetPublicKeyResponse.getDefaultInstance())
    responseObserver.onCompleted()
  }

  override fun healthCheck(request: HealthCheckRequest, responseObserver: StreamObserver<HealthCheckResponse>) {
    responseObserver.onNext(HealthCheckResponse.getDefaultInstance())
    responseObserver.onCompleted()
  }
}
