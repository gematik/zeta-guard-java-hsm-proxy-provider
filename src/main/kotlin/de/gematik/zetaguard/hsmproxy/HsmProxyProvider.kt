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

import de.gematik.zetaguard.hsmproxy.cipher.HsmAesGcmCipherSpi
import de.gematik.zetaguard.hsmproxy.keystore.HsmEcPrivateKey
import de.gematik.zetaguard.hsmproxy.keystore.HsmKeyStoreSpi
import de.gematik.zetaguard.hsmproxy.signature.HsmEcdsaSignatureSpi
import java.security.Provider

/**
 * Java Security Provider for HSM-backed cryptographic operations.
 *
 * Registers three services:
 * - `KeyStore.HSMPROXY` — backed by [HsmKeyStoreSpi]: loads key references and certificates from a `.properties` stream; private key operations are
 *   forwarded to the HSM Proxy via gRPC.
 * - `Signature.SHA256withECDSA` — backed by [HsmEcdsaSignatureSpi]: hashes data locally, sends the digest to the HSM Proxy for signing, and converts
 *   the returned IEEE P1363 signature to ASN.1 DER.
 * - `Cipher.AES/GCM/NoPadding` — backed by [HsmAesGcmCipherSpi]: delegates AES-256-GCM encrypt/decrypt to the HSM Proxy via gRPC.
 *
 * ## Programmatic registration (recommended)
 *
 * ```kotlin
 * Security.addProvider(HsmProxyProvider())
 *
 * val ks = KeyStore.getInstance("HSMPROXY")
 * ks.load(configStream, null)
 * ```
 *
 * ## Static registration via `java.security` extension file
 *
 * Add to a custom security extension file passed with `-Djava.security.properties=/etc/zeta/hsm-security.properties`:
 * ```properties
 * security.provider.N=de.gematik.zetaguard.hsmproxy.HsmProxyProvider
 * ```
 *
 * where `N` is a priority number (lower = higher priority).
 */
class HsmProxyProvider : Provider(NAME, "1.0", "gematik HSM Proxy Java Security Provider — delegates EC key operations to remote HSM via gRPC") {

  companion object {
    const val NAME = "HSMPROXY"

    /** Algorithm name for the KeyStore service registered by this provider. */
    const val KEYSTORE_TYPE = "HSMPROXY"

    /** Algorithm name for the Signature service registered by this provider. */
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    /** Algorithm name for the Cipher service registered by this provider. */
    const val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
  }

  init {
    putService(
        object :
            Service(
                this,
                "Signature",
                "SHA256withECDSA",
                HsmEcdsaSignatureSpi::class.java.name,
                /* aliases */ null,
                /* attrs   */ mapOf("SupportedKeyClasses" to HsmEcPrivateKey::class.java.name),
            ) {}
    )
    putService(object : Service(this, "KeyStore", "HSMPROXY", HsmKeyStoreSpi::class.java.name, null, null) {})
    putService(object : Service(this, "Cipher", "AES/GCM/NoPadding", HsmAesGcmCipherSpi::class.java.name, null, null) {})
  }
}
