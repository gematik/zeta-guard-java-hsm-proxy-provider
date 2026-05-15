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
package de.gematik.zetaguard.hsmproxy.cipher

import de.gematik.zetaguard.hsmproxy.keystore.HsmSecretKey
import java.io.ByteArrayOutputStream
import java.security.AlgorithmParameters
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Key
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.BadPaddingException
import javax.crypto.CipherSpi
import javax.crypto.spec.GCMParameterSpec
import org.slf4j.LoggerFactory

/**
 * [CipherSpi] for `AES/GCM/NoPadding` backed by the HSM Proxy.
 *
 * Encrypt flow:
 * 1. [engineInit] with [javax.crypto.Cipher.ENCRYPT_MODE] and an [HsmSecretKey].
 * 2. [engineUpdate] accumulates plaintext.
 * 3. [engineDoFinal] sends the accumulated plaintext to the HSM Proxy via gRPC `Encrypt`. The IV is generated server-side and stored for
 *    [engineGetIV].
 *
 * Decrypt flow:
 * 1. [engineInit] with [javax.crypto.Cipher.DECRYPT_MODE], an [HsmSecretKey], and a [GCMParameterSpec] containing the IV (from a previous encrypt).
 * 2. [engineUpdate] accumulates ciphertext.
 * 3. [engineDoFinal] sends the accumulated ciphertext to the HSM Proxy via gRPC `Decrypt`.
 *
 * AAD can be supplied via [engineUpdateAAD] before [engineDoFinal].
 */
private const val GCM_TAG_BYTES = 16

class HsmAesGcmCipherSpi : CipherSpi() {

  private val log = LoggerFactory.getLogger(HsmAesGcmCipherSpi::class.java)

  private var hsmKey: HsmSecretKey? = null
  private var opmode: Int = 0
  private var iv: ByteArray? = null
  private val buffer = ByteArrayOutputStream()
  private val aadBuffer = ByteArrayOutputStream()

  // ── Init ─────────────────────────────────────────────────────────────────

  override fun engineInit(opmode: Int, key: Key?, random: SecureRandom?) {
    initInternal(opmode, key, iv = null)
  }

  override fun engineInit(opmode: Int, key: Key?, params: AlgorithmParameterSpec?, random: SecureRandom?) {
    val gcmIv =
        when {
          params == null -> null
          params is GCMParameterSpec -> params.iv
          else -> throw InvalidAlgorithmParameterException("Expected GCMParameterSpec, got ${params.javaClass.name}")
        }
    initInternal(opmode, key, gcmIv)
  }

  override fun engineInit(opmode: Int, key: Key?, params: AlgorithmParameters?, random: SecureRandom?) {
    val gcmIv = params?.getParameterSpec(GCMParameterSpec::class.java)?.iv
    initInternal(opmode, key, gcmIv)
  }

  private fun initInternal(opmode: Int, key: Key?, iv: ByteArray?) {
    hsmKey = (key as? HsmSecretKey) ?: throw InvalidKeyException("HsmAesGcmCipherSpi requires an HsmSecretKey, got: ${key?.javaClass?.name}")
    this.opmode = opmode
    this.iv = iv
    buffer.reset()
    aadBuffer.reset()
    log.debug("engineInit: keyId={} opmode={}", hsmKey!!.keyId, opmode)
  }

  // ── Update ───────────────────────────────────────────────────────────────

  override fun engineUpdate(input: ByteArray, inputOffset: Int, inputLen: Int): ByteArray? {
    buffer.write(input, inputOffset, inputLen)
    return null // all output delivered in engineDoFinal
  }

  override fun engineUpdateAAD(src: ByteArray, offset: Int, len: Int) {
    aadBuffer.write(src, offset, len)
  }

  override fun engineUpdate(input: ByteArray, inputOffset: Int, inputLen: Int, output: ByteArray, outputOffset: Int): Int {
    engineUpdate(input, inputOffset, inputLen)
    return 0
  }

  // ── DoFinal ──────────────────────────────────────────────────────────────

  override fun engineDoFinal(input: ByteArray?, inputOffset: Int, inputLen: Int): ByteArray {
    if (input != null && inputLen > 0) {
      buffer.write(input, inputOffset, inputLen)
    }
    val key = hsmKey ?: throw IllegalStateException("Not initialised — call init() first")
    val aad = aadBuffer.toByteArray()

    return when (opmode) {
      javax.crypto.Cipher.ENCRYPT_MODE -> doEncrypt(key, aad)
      javax.crypto.Cipher.DECRYPT_MODE -> doDecrypt(key, aad)
      else -> throw UnsupportedOperationException("Unsupported cipher mode: $opmode")
    }
  }

  private fun doEncrypt(key: HsmSecretKey, aad: ByteArray): ByteArray {
    val plaintext = buffer.toByteArray()
    log.debug("doEncrypt: keyId={} plaintextLen={} aadLen={}", key.keyId, plaintext.size, aad.size)

    val response =
        try {
          key.grpcClient.encrypt(key.keyId, plaintext, aad)
        } catch (e: Exception) {
          throw BadPaddingException("HSM Proxy encrypt failed for keyId='${key.keyId}': ${e.message}").initCause(e)
        }

    iv = response.iv.toByteArray()
    // Standard JCA GCM convention: return ciphertext || tag (16 bytes appended).
    // Callers pass the combined output to decrypt; doDecrypt splits off the tag.
    return response.ciphertext.toByteArray() + response.tag.toByteArray()
  }

  private fun doDecrypt(key: HsmSecretKey, aad: ByteArray): ByteArray {
    val combined = buffer.toByteArray()
    val decryptIv = iv ?: throw IllegalStateException("IV not set — init with GCMParameterSpec for decrypt")

    // Split ciphertext || tag (last GCM_TAG_BYTES are the authentication tag)
    if (combined.size < GCM_TAG_BYTES) {
      throw BadPaddingException("Input too short for GCM: ${combined.size} bytes (need at least $GCM_TAG_BYTES for the tag)")
    }
    val ciphertext = combined.copyOfRange(0, combined.size - GCM_TAG_BYTES)
    val decryptTag = combined.copyOfRange(combined.size - GCM_TAG_BYTES, combined.size)

    log.debug(
        "doDecrypt: keyId={} ciphertextLen={} ivLen={} tagLen={} aadLen={}",
        key.keyId,
        ciphertext.size,
        decryptIv.size,
        decryptTag.size,
        aad.size,
    )

    val response =
        try {
          key.grpcClient.decrypt(key.keyId, ciphertext, decryptIv, decryptTag, aad)
        } catch (e: Exception) {
          throw BadPaddingException("HSM Proxy decrypt failed for keyId='${key.keyId}': ${e.message}").initCause(e)
        }

    return response.plaintext.toByteArray()
  }

  override fun engineDoFinal(input: ByteArray?, inputOffset: Int, inputLen: Int, output: ByteArray, outputOffset: Int): Int {
    val result = engineDoFinal(input, inputOffset, inputLen)
    System.arraycopy(result, 0, output, outputOffset, result.size)
    return result.size
  }

  // ── Query methods ────────────────────────────────────────────────────────

  override fun engineGetIV(): ByteArray? = iv

  override fun engineGetOutputSize(inputLen: Int): Int = inputLen + 16 // GCM tag overhead

  override fun engineGetBlockSize(): Int = 16 // AES block size

  override fun engineGetParameters(): AlgorithmParameters? =
      iv?.let { AlgorithmParameters.getInstance("GCM").apply { init(GCMParameterSpec(128, it)) } }

  override fun engineSetMode(mode: String) {
    if (!mode.equals("GCM", ignoreCase = true)) throw UnsupportedOperationException("Only GCM mode is supported")
  }

  override fun engineSetPadding(padding: String) {
    if (!padding.equals("NoPadding", ignoreCase = true)) throw UnsupportedOperationException("Only NoPadding is supported")
  }
}
