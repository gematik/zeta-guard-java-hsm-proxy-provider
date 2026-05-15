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
import javax.crypto.SecretKey

/**
 * Phantom secret key for HSM-backed symmetric keys (AES-256-GCM).
 *
 * Holds only a [keyId] string — no key material is stored locally. All encrypt/decrypt operations are delegated to the [HsmProxyGrpcClient].
 *
 * [getEncoded] and [getFormat] intentionally return `null` because there is no local key material to encode.
 */
class HsmSecretKey internal constructor(val keyId: String, internal val grpcClient: HsmProxyGrpcClient) : SecretKey {

  override fun getAlgorithm(): String = "AES"

  /** Returns `null` — key material never leaves the HSM. */
  override fun getEncoded(): ByteArray? = null

  /** Returns `null` — no encoding format since there is no key material. */
  override fun getFormat(): String? = null
}
