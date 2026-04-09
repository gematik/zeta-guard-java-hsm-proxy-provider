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
import de.gematik.zetaguard.hsmproxy.keystore.HsmEcPrivateKey
import de.gematik.zetaguard.hsmproxy.v1.GetPublicKeyRequest
import de.gematik.zetaguard.hsmproxy.v1.GetPublicKeyResponse
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckRequest
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckResponse
import de.gematik.zetaguard.hsmproxy.v1.HsmProxyServiceGrpc
import de.gematik.zetaguard.hsmproxy.v1.SignRequest
import de.gematik.zetaguard.hsmproxy.v1.SignResponse
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import io.grpc.stub.StreamObserver
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import java.security.KeyStore
import java.security.Security
import java.security.Signature

class HsmProxyProviderTest :
    FunSpec({
      val provider = HsmProxyProvider()

      beforeSpec { Security.addProvider(provider) }

      afterSpec { Security.removeProvider(HsmProxyProvider.NAME) }

      // ── Provider metadata ─────────────────────────────────────────────────

      test("provider name is HSMPROXY") { provider.name shouldBe "HSMPROXY" }

      test("provider version is 1.0") { provider.versionStr shouldBe "1.0" }

      test("provider info contains gematik and gRPC") {
        provider.info.shouldContain("gematik")
        provider.info.shouldContain("gRPC")
      }

      // ── Service registration ──────────────────────────────────────────────

      test("KeyStore.HSMPROXY is resolvable after addProvider") {
        val ks = KeyStore.getInstance("HSMPROXY")
        ks shouldNotBe null
      }

      test("KeyStore.HSMPROXY resolves to this provider") {
        val ks = KeyStore.getInstance("HSMPROXY", provider)
        ks shouldNotBe null
      }

      test("Signature.SHA256withECDSA is resolvable after addProvider") {
        // This would normally find the Sun provider too, but we want OURS specifically
        val sig = Signature.getInstance("SHA256withECDSA", provider)
        sig shouldNotBe null
      }

      // ── Constants ─────────────────────────────────────────────────────────

      test("KEYSTORE_TYPE constant matches registered algorithm") { HsmProxyProvider.KEYSTORE_TYPE shouldBe "HSMPROXY" }

      test("SIGNATURE_ALGORITHM constant matches registered algorithm") { HsmProxyProvider.SIGNATURE_ALGORITHM shouldBe "SHA256withECDSA" }

      // ── End-to-end: Provider-resolved Signature signs via HSM ─────────────

      test("Provider-resolved Signature delegates to HsmEcdsaSignatureSpi") {
        // Set up in-process fake gRPC backend
        val serverName = InProcessServerBuilder.generateName()
        val fakeService = ProviderFakeSignService()
        val p1363 = ByteArray(64)
        p1363[31] = 0x01 // r = 1
        p1363[63] = 0x02 // s = 2
        fakeService.nextSignature = p1363

        val server = InProcessServerBuilder.forName(serverName).directExecutor().addService(fakeService).build().start()

        val channel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
        val grpcClient = HsmProxyGrpcClient(channel)
        val key = HsmEcPrivateKey("e2e-key", grpcClient)

        try {
          val sig = Signature.getInstance("SHA256withECDSA", provider)
          sig.initSign(key)
          sig.update("hello".toByteArray())
          val der = sig.sign()

          // DER SEQUENCE { INTEGER 1, INTEGER 2 } = 30 06 02 01 01 02 01 02
          der shouldBe byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)
        } finally {
          grpcClient.close()
          server.shutdown()
        }
      }
    })

// ── In-process fake for Provider tests ───────────────────────────────────────

private class ProviderFakeSignService : HsmProxyServiceGrpc.HsmProxyServiceImplBase() {
  var nextSignature: ByteArray = ByteArray(64)

  override fun sign(request: SignRequest, responseObserver: StreamObserver<SignResponse>) {
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
