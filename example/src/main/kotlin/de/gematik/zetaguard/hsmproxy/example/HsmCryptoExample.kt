/*-
* #%L
* java-hsm-proxy-provider-example
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
package de.gematik.zetaguard.hsmproxy.example

import de.gematik.zetaguard.hsmproxy.HsmCrypto

// Demonstrates the simplified HsmCrypto API for envelope encryption.
//
// Start hsm_sim first: docker compose up (see docker-compose.yml in this directory)
// Then run: mvn compile exec:java -Dexec.mainClass="de.gematik.zetaguard.hsmproxy.example.HsmCryptoExampleKt"
//
// Prerequisites:
//   - HSM_PROXY_ENDPOINT env var set (or pass --endpoint)
//   - A running HSM Proxy / hsm_sim

private const val DEFAULT_ENDPOINT = "localhost:15051"
private const val DEFAULT_KEK_ID = "vau-db-kek-v1"

fun main(args: Array<String>) {
  val endpoint = args.option("--endpoint") ?: DEFAULT_ENDPOINT
  val kekId = args.option("--kek-id") ?: DEFAULT_KEK_ID

  println("HsmCrypto Example")
  println("  endpoint: $endpoint")
  println("  kek-id  : $kekId")
  println()

  val crypto = HsmCrypto(endpoint)

  // 1. Encrypt a DEK — returns a single blob (iv || ciphertext || tag)
  val dek = "this-is-a-32-byte-data-enc-key!".toByteArray()
  val encrypted = crypto.encrypt(dek, keyId = kekId)
  println("[1] Encrypted: ${dek.size} bytes → ${encrypted.size} bytes")

  // 2. Decrypt — pass the blob back, get the original DEK
  val decrypted = crypto.decrypt(encrypted, keyId = kekId)
  println("[2] Decrypted: ${String(decrypted)}")
  check(decrypted.contentEquals(dek)) { "Round-trip failed" }

  // 3. With AAD — prevents ciphertext swapping between DB rows
  val aad = "row-42".toByteArray()
  val encryptedWithAad = crypto.encrypt(dek, aad = aad, keyId = kekId)
  val decryptedWithAad = crypto.decrypt(encryptedWithAad, aad = aad, keyId = kekId)
  println("[3] Round-trip with AAD: ${String(decryptedWithAad)}")
  check(decryptedWithAad.contentEquals(dek)) { "AAD round-trip failed" }

  println()
  println("Success.")
}

private fun Array<String>.option(name: String): String? {
  val idx = indexOf(name)
  return if (idx >= 0 && idx + 1 < size) get(idx + 1) else null
}
