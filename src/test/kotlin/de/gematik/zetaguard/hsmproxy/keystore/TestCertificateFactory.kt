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

import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/**
 * Test utility that generates a self-signed EC P-256 certificate and writes it to a temp PEM file.
 *
 * Used only in tests — BouncyCastle is a test-scoped dependency.
 */
object TestCertificateFactory {

  /**
   * Generates a self-signed EC P-256 certificate valid for 1 year.
   *
   * @return Pair of the [X509Certificate] and the temp [File] containing the PEM. Caller is responsible for deleting the file after use.
   */
  fun generateSelfSignedEcCert(): Pair<X509Certificate, File> {
    val keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    val now = Date()
    val expiry = Date(now.time + 365L * 24 * 3_600 * 1_000)
    val subject = X500Name("CN=hsm-test,O=gematik,C=DE")

    val certHolder =
        JcaX509v3CertificateBuilder(subject, BigInteger.ONE, now, expiry, subject, keyPair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private))

    val cert = JcaX509CertificateConverter().getCertificate(certHolder)

    val pem = buildString {
      appendLine("-----BEGIN CERTIFICATE-----")
      append(Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded))
      appendLine()
      appendLine("-----END CERTIFICATE-----")
    }

    val file = File.createTempFile("hsm-test-cert-", ".pem").also { it.writeText(pem) }

    return cert to file
  }

  /** Encodes an [X509Certificate] as a PEM string. */
  fun toPem(cert: X509Certificate): String = buildString {
    appendLine("-----BEGIN CERTIFICATE-----")
    append(Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(cert.encoded))
    appendLine()
    appendLine("-----END CERTIFICATE-----")
  }
}
