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
import java.io.ByteArrayInputStream
import java.io.FileInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStoreException
import java.security.KeyStoreSpi
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.Properties
import org.slf4j.LoggerFactory

/**
 * [KeyStoreSpi] implementation backed by the HSM Proxy.
 *
 * Configuration is loaded from a `.properties` [InputStream] passed to [engineLoad]:
 * ```properties
 * hsm.endpoint=localhost:50051
 *
 * keys.my-tls-key.key_id=zeta-guard-tls-es256-v1
 * keys.my-tls-key.cert=/etc/zeta/certs/tls.pem   # optional — omit to fetch cert via gRPC
 * ```
 *
 * The certificate (public, safe to store on disk) is loaded from the configured PEM file, or fetched from the HSM Proxy via gRPC if no `cert` path is
 * given. The private key never leaves the HSM — [engineGetKey] returns an [HsmEcPrivateKey] that holds only a `key_id` reference and a gRPC client
 * handle.
 *
 * This KeyStore is **read-only**. All write operations throw [UnsupportedOperationException].
 *
 * [engineLoad] must be called before any other method. The gRPC channel is created lazily — the call does not block or require the proxy to be
 * reachable yet.
 */
private const val READ_ONLY_MSG = "HsmKeyStoreSpi is read-only"

open class HsmKeyStoreSpi : KeyStoreSpi() {

  private val log = LoggerFactory.getLogger(HsmKeyStoreSpi::class.java)

  private data class Entry(val keyId: String, val certificate: X509Certificate)

  private var entries: Map<String, Entry> = emptyMap()

  /** Exposed internally so [HsmEcdsaSignatureSpi] can share the same channel. */
  internal var grpcClient: HsmProxyGrpcClient? = null
    private set

  // ── Load ─────────────────────────────────────────────────────────────────

  /**
   * Initialises the KeyStore from a `.properties` [stream], or — when the stream is null or contains no `keys.*` entries — from the
   * `HSM_PROXY_ENDPOINT` and `HSM_PROXY_KEY_ID` environment variables.
   *
   * **Properties-file mode** (normal path): stream must contain `hsm.endpoint` and at least one `keys.<alias>.key_id` entry. An optional
   * `keys.<alias>.cert` path loads the certificate from disk; if absent the certificate is fetched via the `GetCertificate` gRPC RPC.
   *
   * **Env-var fallback** (when stream is null or contains no `keys.*` entries): reads `HSM_PROXY_ENDPOINT` and `HSM_PROXY_KEY_ID`; creates a single
   * entry with alias `"tls"` whose certificate is always fetched via gRPC. Both env vars must be set or a [KeyStoreException] is thrown.
   *
   * [password] is ignored — access control is handled by mTLS on the gRPC channel (future).
   *
   * @throws KeyStoreException if required config is missing or a cert cannot be loaded.
   */
  override fun engineLoad(stream: InputStream?, password: CharArray?) {
    val props = stream?.let { s -> Properties().also { it.load(s) } } ?: Properties()

    val configuredKeys = props.stringPropertyNames().filter { it.startsWith("keys.") && it.endsWith(".key_id") }

    val endpoint =
        props.getProperty("hsm.endpoint")
            ?: readEnv("HSM_PROXY_ENDPOINT")
            ?: throw KeyStoreException("hsm.endpoint not set: provide a .properties config stream or set HSM_PROXY_ENDPOINT env var")

    grpcClient = buildGrpcClient(endpoint)

    entries =
        if (configuredKeys.isNotEmpty()) {
          configuredKeys.associate { prop ->
            val alias = prop.removePrefix("keys.").removeSuffix(".key_id")
            val keyId = props.getProperty(prop) ?: throw KeyStoreException("Empty key_id for alias '$alias'")
            val certPath = props.getProperty("keys.$alias.cert")
            val cert = if (certPath != null) loadCertificateFromFile(alias, certPath) else loadCertificateFromGrpc(alias, keyId)
            alias to Entry(keyId, cert)
          }
        } else {
          // Env-var fallback: single entry with alias "tls"
          val keyId =
              readEnv("HSM_PROXY_KEY_ID")
                  ?: throw KeyStoreException("No keys configured: set keys.<alias>.key_id properties or HSM_PROXY_KEY_ID env var")
          val cert = loadCertificateFromGrpc("tls", keyId)
          mapOf("tls" to Entry(keyId, cert))
        }

    log.info("engineLoad: {} key entries loaded (endpoint={})", entries.size, endpoint)
  }

  /** Overridable factory for the gRPC client. Extracted so tests can inject an in-process channel without modifying the production code path. */
  internal open fun buildGrpcClient(endpoint: String): HsmProxyGrpcClient = HsmProxyGrpcClient(endpoint)

  /** Overridable env-var reader. Extracted so tests can supply fake env vars without JVM restarts. */
  internal open fun readEnv(name: String): String? = System.getenv(name)

  private fun loadCertificateFromFile(alias: String, path: String): X509Certificate =
      try {
        FileInputStream(path).use { fis -> parseCertificatePem(alias, fis) }
      } catch (e: KeyStoreException) {
        throw e
      } catch (e: Exception) {
        throw KeyStoreException("Failed to load certificate for alias '$alias' from '$path': ${e.message}", e)
      }

  private fun loadCertificateFromGrpc(alias: String, keyId: String): X509Certificate =
      try {
        val pem =
            grpcClient!!.getCertificate(keyId).certificatePem.also {
              if (it.isBlank()) throw KeyStoreException("Empty certificate PEM returned for alias '$alias'")
            }
        parseCertificatePem(alias, ByteArrayInputStream(pem.toByteArray()))
      } catch (e: KeyStoreException) {
        throw e
      } catch (e: Exception) {
        throw KeyStoreException("Failed to fetch certificate for alias '$alias' (key_id='$keyId') from HSM Proxy: ${e.message}", e)
      }

  private fun parseCertificatePem(alias: String, stream: InputStream): X509Certificate =
      try {
        CertificateFactory.getInstance("X.509").generateCertificate(stream) as X509Certificate
      } catch (e: Exception) {
        throw KeyStoreException("Failed to parse X.509 certificate for alias '$alias': ${e.message}", e)
      }

  // ── Read operations ───────────────────────────────────────────────────────

  /**
   * Returns an [HsmEcPrivateKey] for the given [alias], or `null` if the alias is unknown.
   *
   * The returned key holds the `key_id` and a reference to the shared [HsmProxyGrpcClient]. No key material is returned.
   */
  override fun engineGetKey(alias: String, password: CharArray?): Key? {
    val entry = entries[alias] ?: return null
    val client = grpcClient ?: throw KeyStoreException("KeyStore not initialised — call KeyStore.load() first")
    return HsmEcPrivateKey(entry.keyId, client)
  }

  override fun engineGetCertificate(alias: String): Certificate? = entries[alias]?.certificate

  override fun engineGetCertificateChain(alias: String): Array<Certificate>? = entries[alias]?.let { arrayOf(it.certificate) }

  override fun engineGetCertificateAlias(cert: Certificate): String? = entries.entries.find { it.value.certificate == cert }?.key

  /** Returns the certificate's `notBefore` date, or `null` if the alias is unknown. */
  override fun engineGetCreationDate(alias: String): Date? = entries[alias]?.certificate?.notBefore

  override fun engineAliases(): Enumeration<String> = Collections.enumeration(entries.keys)

  override fun engineContainsAlias(alias: String): Boolean = alias in entries

  override fun engineSize(): Int = entries.size

  override fun engineIsKeyEntry(alias: String): Boolean = alias in entries

  override fun engineIsCertificateEntry(alias: String): Boolean = false

  // ── Write operations (not supported) ─────────────────────────────────────

  override fun engineStore(stream: OutputStream?, password: CharArray?): Unit = throw UnsupportedOperationException(READ_ONLY_MSG)

  override fun engineSetKeyEntry(alias: String, key: Key, password: CharArray?, chain: Array<out Certificate>?): Unit =
      throw UnsupportedOperationException(READ_ONLY_MSG)

  override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<out Certificate>?): Unit =
      throw UnsupportedOperationException(READ_ONLY_MSG)

  override fun engineSetCertificateEntry(alias: String, cert: Certificate): Unit = throw UnsupportedOperationException(READ_ONLY_MSG)

  override fun engineDeleteEntry(alias: String): Unit = throw UnsupportedOperationException(READ_ONLY_MSG)
}
