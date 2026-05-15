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
import javax.crypto.SecretKey

class HsmSecretKeyTest :
    FunSpec({
      val channel = InProcessChannelBuilder.forName("hsm-secret-key-test").directExecutor().build()
      val client = HsmProxyGrpcClient(channel)

      afterSpec { client.close() }

      test("getAlgorithm returns AES") { HsmSecretKey("any-key-id", client).algorithm shouldBe "AES" }

      test("getEncoded returns null — no key material stored locally") { HsmSecretKey("any-key-id", client).encoded shouldBe null }

      test("getFormat returns null — no encoding format without key material") { HsmSecretKey("any-key-id", client).format shouldBe null }

      test("keyId is stored and accessible") {
        val key = HsmSecretKey("vau-db-kek-v1", client)
        key.keyId shouldBe "vau-db-kek-v1"
      }

      test("implements SecretKey interface") { HsmSecretKey("k", client).shouldBeInstanceOf<SecretKey>() }

      test("different key IDs produce independent instances") {
        val k1 = HsmSecretKey("kek-a", client)
        val k2 = HsmSecretKey("kek-b", client)
        k1.keyId shouldBe "kek-a"
        k2.keyId shouldBe "kek-b"
      }
    })
