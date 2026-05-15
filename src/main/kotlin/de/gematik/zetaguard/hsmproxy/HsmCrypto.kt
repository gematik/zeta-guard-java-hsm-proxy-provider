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

import de.gematik.zetaguard.hsmproxy.grpc.HsmProxyGrpcClient
import java.io.Closeable

/**
 * High-level API for HSM-backed AES-256-GCM encryption/decryption.
 *
 * Wraps [HsmProxyGrpcClient] and handles IV/tag packing so callers deal with a single `ByteArray` blob.
 *
 * **Simplest usage (env-var driven, zero config):**
 *
 * ```kotlin
 * // Set HSM_PROXY_ENDPOINT=hsm-proxy:50051 and HSM_PROXY_KEK_ID=vau-db-kek-v1, then:
 * val encrypted = HsmCrypto.encrypt(plaintext)
 * val decrypted = HsmCrypto.decrypt(encrypted)
 * ```
 *
 * **With explicit keyId (overrides HSM_PROXY_KEK_ID, e.g. for key rotation or multi-tenant):**
 *
 * ```kotlin
 * val encrypted = HsmCrypto.encrypt("other-kek", plaintext)
 * ```
 *
 * **With AAD (prevents ciphertext swapping between DB rows):**
 *
 * ```kotlin
 * val encrypted = HsmCrypto.encrypt(plaintext, aad = "row-42".toByteArray())
 * val decrypted = HsmCrypto.decrypt(encrypted, aad = "row-42".toByteArray())
 * ```
 *
 * **With explicit endpoint (tests, non-default environments):**
 *
 * ```kotlin
 * val crypto = HsmCrypto("localhost:15051")
 * val encrypted = crypto.encrypt("vau-kek", plaintext)
 * ```
 *
 * The returned blob layout is `iv (12 bytes) || ciphertext || tag (16 bytes)`. This is a self-contained value: store it as-is in a database column or
 * protobuf field. No separate IV or tag storage needed.
 *
 * Thread-safe: the underlying gRPC channel handles concurrent calls.
 */
class HsmCrypto internal constructor(private val client: HsmProxyGrpcClient) : Closeable by client {

  constructor(endpoint: String) : this(HsmProxyGrpcClient(endpoint))

  /**
   * Encrypts [plaintext] with AES-256-GCM under the HSM key [keyId].
   *
   * @param keyId the symmetric key identifier in the HSM. Defaults to `HSM_PROXY_KEK_ID` env var.
   * @param plaintext the data to encrypt
   * @param aad optional authenticated additional data (e.g. row ID)
   * @return `iv (12) || ciphertext || tag (16)` — a single self-contained blob
   */
  fun encrypt(plaintext: ByteArray, aad: ByteArray = ByteArray(0), keyId: String = defaultKekId()): ByteArray {
    val r = client.encrypt(keyId, plaintext, aad)
    return r.iv.toByteArray() + r.ciphertext.toByteArray() + r.tag.toByteArray()
  }

  /**
   * Decrypts a blob previously produced by [encrypt].
   *
   * @param data the blob returned by [encrypt] (`iv || ciphertext || tag`)
   * @param aad the AAD used during encryption (must match exactly, or empty if none was used)
   * @param keyId the symmetric key identifier in the HSM. Defaults to `HSM_PROXY_KEK_ID` env var.
   * @return the original plaintext
   * @throws IllegalArgumentException if [data] is too short to contain an IV + tag
   * @throws io.grpc.StatusRuntimeException if the HSM rejects the operation (wrong key, tampered data, AAD mismatch)
   */
  fun decrypt(data: ByteArray, aad: ByteArray = ByteArray(0), keyId: String = defaultKekId()): ByteArray {
    require(data.size > GCM_IV_SIZE + GCM_TAG_SIZE) { "Encrypted data too short: ${data.size} bytes (minimum ${GCM_IV_SIZE + GCM_TAG_SIZE + 1})" }
    val iv = data.copyOfRange(0, GCM_IV_SIZE)
    val ciphertext = data.copyOfRange(GCM_IV_SIZE, data.size - GCM_TAG_SIZE)
    val tag = data.copyOfRange(data.size - GCM_TAG_SIZE, data.size)
    return client.decrypt(keyId, ciphertext, iv, tag, aad).plaintext.toByteArray()
  }

  companion object {
    const val ENV_ENDPOINT = "HSM_PROXY_ENDPOINT"
    const val ENV_KEK_ID = "HSM_PROXY_KEK_ID"
    private const val GCM_IV_SIZE = 12
    private const val GCM_TAG_SIZE = 16

    /** Overridable env-var reader — extracted so tests can supply fake values without JVM restarts. */
    internal var getenv: (String) -> String? = System::getenv

    @Volatile internal var defaultInstance: HsmCrypto? = null

    private fun default(): HsmCrypto =
        defaultInstance
            ?: synchronized(this) {
              defaultInstance
                  ?: run {
                    val endpoint = getenv(ENV_ENDPOINT) ?: throw IllegalStateException("$ENV_ENDPOINT environment variable is not set")
                    HsmCrypto(endpoint).also { defaultInstance = it }
                  }
            }

    internal fun defaultKekId(): String =
        getenv(ENV_KEK_ID) ?: throw IllegalStateException("$ENV_KEK_ID environment variable is not set and no keyId was provided")

    /** Resets the cached default instance. Used by tests to ensure a clean state. */
    internal fun reset() {
      defaultInstance = null
      getenv = System::getenv
    }

    /** Encrypts using the default instance (reads `HSM_PROXY_ENDPOINT` and `HSM_PROXY_KEK_ID` from the environment). */
    fun encrypt(plaintext: ByteArray, aad: ByteArray = ByteArray(0), keyId: String = defaultKekId()): ByteArray =
        default().encrypt(plaintext, aad, keyId)

    /** Decrypts using the default instance (reads `HSM_PROXY_ENDPOINT` and `HSM_PROXY_KEK_ID` from the environment). */
    fun decrypt(data: ByteArray, aad: ByteArray = ByteArray(0), keyId: String = defaultKekId()): ByteArray = default().decrypt(data, aad, keyId)
  }
}
