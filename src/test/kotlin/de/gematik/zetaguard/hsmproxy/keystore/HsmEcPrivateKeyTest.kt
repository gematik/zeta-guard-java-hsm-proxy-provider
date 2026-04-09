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

import de.gematik.zetaguard.hsmproxy.grpc.HsmProxyGrpcClient
import io.grpc.inprocess.InProcessChannelBuilder
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.PrivateKey

class HsmEcPrivateKeyTest :
    FunSpec({
      // Use an in-process channel so no real connection is needed
      val channel = InProcessChannelBuilder.forName("hsm-ec-key-test").directExecutor().build()
      val client = HsmProxyGrpcClient(channel)

      afterSpec { client.close() }

      test("getAlgorithm returns EC") { HsmEcPrivateKey("any-key-id", client).getAlgorithm() shouldBe "EC" }

      test("getEncoded returns null — no key material stored locally") { HsmEcPrivateKey("any-key-id", client).getEncoded() shouldBe null }

      test("getFormat returns null — no encoding format without key material") { HsmEcPrivateKey("any-key-id", client).getFormat() shouldBe null }

      test("keyId is stored and accessible") {
        val key = HsmEcPrivateKey("zeta-guard-keycloak-tls-es256-v1", client)
        key.keyId shouldBe "zeta-guard-keycloak-tls-es256-v1"
      }

      test("implements PrivateKey interface") { HsmEcPrivateKey("k", client).shouldBeInstanceOf<PrivateKey>() }

      test("different key IDs produce independent instances") {
        val key1 = HsmEcPrivateKey("key-a", client)
        val key2 = HsmEcPrivateKey("key-b", client)
        key1.keyId shouldBe "key-a"
        key2.keyId shouldBe "key-b"
      }
    })
