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

import de.gematik.zetaguard.hsmproxy.keystore.HsmEcPrivateKey
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SignatureException
import java.security.SignatureSpi
import org.slf4j.LoggerFactory

/**
 * [SignatureSpi] for `SHA256withECDSA` backed by the HSM Proxy.
 *
 * Signing flow:
 * 1. [engineInitSign] — accepts an [HsmEcPrivateKey]; no other key type is supported.
 * 2. [engineUpdate] — accumulates data in a [ByteArrayOutputStream].
 * 3. [engineSign] — SHA-256-hashes the accumulated bytes locally, sends the 32-byte digest to the HSM Proxy via gRPC, and converts the IEEE P1363
 *    response (raw R‖S, 64 bytes) to ASN.1 DER.
 *
 * Verification is **not** supported. `SHA256withECDSA` verification should be performed with the standard Sun/BC provider using the public key from
 * the certificate — no HSM involvement needed.
 */
class HsmEcdsaSignatureSpi : SignatureSpi() {

  private val log = LoggerFactory.getLogger(HsmEcdsaSignatureSpi::class.java)

  private var hsmKey: HsmEcPrivateKey? = null
  private val buffer = ByteArrayOutputStream()

  // ── Init ─────────────────────────────────────────────────────────────────

  override fun engineInitSign(privateKey: PrivateKey?) {
    hsmKey =
        (privateKey as? HsmEcPrivateKey)
            ?: throw InvalidKeyException("HsmEcdsaSignatureSpi requires an HsmEcPrivateKey, got: ${privateKey?.javaClass?.name}")
    buffer.reset()
    log.debug("engineInitSign: keyId={}", hsmKey!!.keyId)
  }

  override fun engineInitVerify(publicKey: PublicKey?): Unit =
      throw UnsupportedOperationException("Verification is not supported by HsmEcdsaSignatureSpi — use the standard provider")

  // ── Update ───────────────────────────────────────────────────────────────

  override fun engineUpdate(b: Byte) {
    buffer.write(b.toInt())
  }

  override fun engineUpdate(b: ByteArray, off: Int, len: Int) {
    buffer.write(b, off, len)
  }

  // ── Sign ─────────────────────────────────────────────────────────────────

  /**
   * Hashes the buffered data with SHA-256, delegates signing to the HSM Proxy, and converts the IEEE P1363 signature (64-byte R‖S) returned by the
   * proxy to ASN.1 DER.
   *
   * @throws SignatureException if the key was not initialised or the HSM call fails.
   */
  override fun engineSign(): ByteArray {
    val key = hsmKey ?: throw SignatureException("Not initialised — call initSign() first")

    val digest = sha256(buffer.toByteArray())
    log.debug("engineSign: keyId={}, digestLen={}", key.keyId, digest.size)

    val p1363 =
        try {
          key.grpcClient.sign(key.keyId, digest)
        } catch (e: Exception) {
          throw SignatureException("HSM Proxy signing failed for keyId='${key.keyId}': ${e.message}", e)
        }

    return p1363ToDer(p1363)
  }

  // ── Verify / deprecated parameter API ────────────────────────────────────

  override fun engineVerify(sigBytes: ByteArray?): Boolean =
      throw UnsupportedOperationException("Verification is not supported by HsmEcdsaSignatureSpi — use the standard provider")

  @Suppress("OVERRIDE_DEPRECATION")
  override fun engineSetParameter(param: String?, value: Any?): Unit = throw UnsupportedOperationException("engineSetParameter is not supported")

  @Suppress("OVERRIDE_DEPRECATION")
  override fun engineGetParameter(param: String?): Any? = throw UnsupportedOperationException("engineGetParameter is not supported")

  // ── Helpers ───────────────────────────────────────────────────────────────

  private fun sha256(data: ByteArray): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(data)

  /**
   * Converts an IEEE P1363 EC signature (raw R‖S, exactly 64 bytes for P-256) to ASN.1 DER.
   *
   * DER SEQUENCE { INTEGER r, INTEGER s }
   *
   * Both [BigInteger] values are encoded as signed big-endian with a leading 0x00 byte if the high bit is set (to keep the value positive in two's
   * complement).
   *
   * @throws SignatureException if [p1363] is not exactly 64 bytes.
   */
  internal fun p1363ToDer(p1363: ByteArray): ByteArray {
    if (p1363.size != 64) {
      throw SignatureException("Expected 64-byte IEEE P1363 signature (R‖S for P-256), got ${p1363.size} bytes")
    }

    val r = BigInteger(1, p1363.copyOfRange(0, 32))
    val s = BigInteger(1, p1363.copyOfRange(32, 64))

    val rBytes = r.toByteArray() // may have leading 0x00 to indicate positive
    val sBytes = s.toByteArray()

    // DER INTEGER tag=0x02, SEQUENCE tag=0x30
    val seqContent = derInteger(rBytes) + derInteger(sBytes)
    return byteArrayOf(0x30, seqContent.size.toByte()) + seqContent
  }

  private fun derInteger(value: ByteArray): ByteArray = byteArrayOf(0x02, value.size.toByte()) + value
}
