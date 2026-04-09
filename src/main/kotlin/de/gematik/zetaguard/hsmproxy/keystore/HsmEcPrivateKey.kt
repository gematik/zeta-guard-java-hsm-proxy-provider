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
import java.security.PrivateKey

/**
 * Phantom private key for HSM-backed EC keys.
 *
 * Holds only a [keyId] string — no key material is stored locally. All cryptographic operations are delegated to the [HsmProxyGrpcClient].
 *
 * [getEncoded] and [getFormat] intentionally return `null` because there is no local key material to encode. Any code that tries to export the raw
 * key bytes (e.g. serialisation, PKCS#12 export) will receive `null` and must handle it.
 *
 * The [grpcClient] is `internal` — it is used by [HsmEcdsaSignatureSpi] within this module to delegate signing, and is not part of the public API.
 */
class HsmEcPrivateKey internal constructor(val keyId: String, internal val grpcClient: HsmProxyGrpcClient) : PrivateKey {

  override fun getAlgorithm(): String = "EC"

  /** Returns `null` — key material never leaves the HSM. */
  override fun getEncoded(): ByteArray? = null

  /** Returns `null` — no encoding format since there is no key material. */
  override fun getFormat(): String? = null
}
