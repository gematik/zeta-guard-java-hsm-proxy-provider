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
package de.gematik.zetaguard.hsmproxy.grpc

import com.google.protobuf.ByteString
import de.gematik.zetaguard.hsmproxy.v1.DigestAlgorithm
import de.gematik.zetaguard.hsmproxy.v1.GetCertificateRequest
import de.gematik.zetaguard.hsmproxy.v1.GetCertificateResponse
import de.gematik.zetaguard.hsmproxy.v1.GetPublicKeyRequest
import de.gematik.zetaguard.hsmproxy.v1.GetPublicKeyResponse
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckRequest
import de.gematik.zetaguard.hsmproxy.v1.HealthCheckResponse
import de.gematik.zetaguard.hsmproxy.v1.HsmProxyServiceGrpc
import de.gematik.zetaguard.hsmproxy.v1.SignRequest
import io.grpc.ManagedChannel
import io.grpc.ManagedChannelBuilder
import java.io.Closeable
import java.util.concurrent.TimeUnit
import org.slf4j.LoggerFactory

private val DEFAULT_DEADLINE_SECONDS = 10L

/**
 * gRPC client for the HSM Proxy service.
 *
 * Manages a single [ManagedChannel] for the lifetime of this instance. The channel reconnects automatically on transient failures (built-in gRPC
 * behaviour).
 *
 * Usage:
 * ```kotlin
 * HsmProxyGrpcClient("localhost:50051").use { client ->
 *   val signature = client.sign("my-key-id", digest)
 * }
 * ```
 *
 * Thread-safe: the underlying blocking stub and channel are both thread-safe.
 *
 * NOTE: Plain gRPC (no TLS). mTLS support (requirement A_28830) is deferred. To add mTLS, replace [ManagedChannelBuilder.usePlaintext] with
 * [io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder.sslContext].
 */
class HsmProxyGrpcClient internal constructor(private val channel: ManagedChannel) : Closeable {

  /** Creates a client connected to [endpoint] (e.g. `"localhost:50051"`). */
  constructor(endpoint: String) : this(ManagedChannelBuilder.forTarget(endpoint).usePlaintext().build())

  private val stub: HsmProxyServiceGrpc.HsmProxyServiceBlockingStub = HsmProxyServiceGrpc.newBlockingStub(channel)

  private val log = LoggerFactory.getLogger(HsmProxyGrpcClient::class.java)

  /**
   * Signs a pre-computed digest with the key identified by [keyId].
   *
   * [digest] must already be the SHA-256 hash of the data to sign (32 bytes for P-256). The proxy receives it with [DigestAlgorithm.NONE] — no
   * further hashing is performed.
   *
   * @return Signature bytes in IEEE P1363 format (raw R‖S, 64 bytes for P-256). Callers that need ASN.1 DER (e.g. Java TLS) must convert — see
   *   [HsmEcdsaSignatureSpi].
   * @throws io.grpc.StatusRuntimeException on any gRPC-level error.
   */
  fun sign(keyId: String, digest: ByteArray): ByteArray {
    log.debug("sign: keyId={} digestLen={}", keyId, digest.size)
    val request = SignRequest.newBuilder().setKeyId(keyId).setData(ByteString.copyFrom(digest)).setAlgorithm(DigestAlgorithm.NONE).build()
    val response = stub.withDeadlineAfter(DEFAULT_DEADLINE_SECONDS, TimeUnit.SECONDS).sign(request)
    log.debug("sign: keyId={} signatureLen={}", keyId, response.signature.size())
    return response.signature.toByteArray()
  }

  /**
   * Retrieves the public key for [keyId].
   *
   * The response contains the public key in multiple formats (PEM, DER, JWK). Use PEM/DER for TLS certificate matching and JWK for OIDC/Keycloak.
   *
   * @throws io.grpc.StatusRuntimeException on any gRPC-level error.
   */
  fun getPublicKey(keyId: String): GetPublicKeyResponse {
    log.debug("getPublicKey: keyId={}", keyId)
    val request = GetPublicKeyRequest.newBuilder().setKeyId(keyId).build()
    return stub.withDeadlineAfter(DEFAULT_DEADLINE_SECONDS, TimeUnit.SECONDS).getPublicKey(request)
  }

  /**
   * Retrieves the X.509 certificate for [keyId] from the HSM Proxy.
   *
   * The response contains the leaf certificate in PEM format and optionally the full chain. Used by [HsmKeyStoreSpi] at load time when no cert file
   * path is configured.
   *
   * @throws io.grpc.StatusRuntimeException on any gRPC-level error.
   */
  fun getCertificate(keyId: String): GetCertificateResponse {
    log.debug("getCertificate: keyId={}", keyId)
    val request = GetCertificateRequest.newBuilder().setKeyId(keyId).build()
    return stub.withDeadlineAfter(DEFAULT_DEADLINE_SECONDS, TimeUnit.SECONDS).getCertificate(request)
  }

  /**
   * Checks whether the HSM Proxy and its HSM backend are reachable and operational.
   *
   * Intended for startup validation and liveness probes.
   *
   * @throws io.grpc.StatusRuntimeException if the proxy itself is unreachable.
   */
  fun healthCheck(): HealthCheckResponse {
    log.debug("healthCheck")
    return stub.withDeadlineAfter(DEFAULT_DEADLINE_SECONDS, TimeUnit.SECONDS).healthCheck(HealthCheckRequest.getDefaultInstance())
  }

  /**
   * Shuts down the underlying gRPC channel gracefully.
   *
   * Waits up to 5 seconds for in-flight RPCs to complete before forcing shutdown.
   */
  override fun close() {
    log.debug("closing channel")
    channel.shutdown()
    if (!channel.awaitTermination(5, TimeUnit.SECONDS)) {
      log.warn("channel did not terminate within 5 s — forcing shutdown")
      channel.shutdownNow()
    }
  }
}
