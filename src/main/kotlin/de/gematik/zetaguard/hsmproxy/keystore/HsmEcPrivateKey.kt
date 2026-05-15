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
import java.math.BigInteger
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECParameterSpec

/**
 * Phantom private key for HSM-backed EC keys — holds a [keyId] reference and the public curve parameters [ecParams]; no secret material is stored
 * locally. All cryptographic operations are delegated to the [HsmProxyGrpcClient] (`internal`, used by [HsmEcdsaSignatureSpi]).
 *
 * Implements [ECPrivateKey] so JCE consumers can introspect the curve via [getParams] and so [HsmProxyProvider] can advertise
 * `SupportedKeyClasses=HsmEcPrivateKey` to enable provider auto-resolution from `Signature.getInstance("SHA256withECDSA")` without an explicit
 * provider argument.
 * - [getEncoded] returns `null` (no local key material).
 * - [getFormat] returns `"PKCS#8"` — required because some JDK internals (e.g. PKCS12KeyStore) call `getFormat().equals(...)` without null-checking.
 * - [getS] always throws — the private scalar never leaves the HSM.
 */
class HsmEcPrivateKey internal constructor(val keyId: String, private val ecParams: ECParameterSpec, internal val grpcClient: HsmProxyGrpcClient) :
    ECPrivateKey {

  override fun getAlgorithm(): String = "EC"

  /** Returns `null` — key material never leaves the HSM. */
  override fun getEncoded(): ByteArray? = null

  /** Returns `"PKCS#8"` — standard private key format identifier, required by JDK KeyStore internals even though [getEncoded] returns `null`. */
  override fun getFormat(): String = "PKCS#8"

  /**
   * Returns the public EC curve parameters extracted from the entry's certificate — needed by JCE consumers that introspect the key before signing.
   */
  override fun getParams(): ECParameterSpec = ecParams

  /** Always throws — the private scalar stays in the HSM. */
  override fun getS(): BigInteger {
    throw UnsupportedOperationException("Private scalar stays in the HSM")
  }
}
