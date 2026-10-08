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

import java.security.SignatureException

/**
 * [SignatureSpi] for `SHA256withECDSAinP1363Format` backed by the HSM Proxy — returns raw 64-byte R‖S, no DER wrapping.
 *
 * Required by the JDK's TLS 1.3 implementation: the `ecdsa_secp256r1_sha256` SignatureScheme uses this algorithm name. Without it, TLS 1.3 handshakes
 * silently fail (server closes after ClientHello with no compatible signature scheme).
 */
class HsmEcdsaP1363SignatureSpi : HsmEcdsaSignatureSpi() {

  override fun engineSign(): ByteArray {
    val key = hsmKey ?: throw SignatureException("Not initialised — call initSign() first")
    val digest = sha256(buffer.toByteArray())
    return try {
      key.grpcClient.sign(key.keyId, digest)
    } catch (e: Exception) {
      throw SignatureException("HSM Proxy signing failed for keyId='${key.keyId}': ${e.message}", e)
    }
  }
}
