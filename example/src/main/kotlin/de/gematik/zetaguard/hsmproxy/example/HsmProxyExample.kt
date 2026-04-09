/*-
* #%L
* java-hsm-proxy-provider-example
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
package de.gematik.zetaguard.hsmproxy.example

import de.gematik.zetaguard.hsmproxy.HsmProxyProvider
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.Signature

// Start hsm_sim first:  docker compose up  (see docker-compose.yml in this directory)
// Then run:             mvn compile exec:java
// Custom endpoint:      mvn compile exec:java -Dexec.args="--endpoint host:port"

private const val DEFAULT_ENDPOINT = "localhost:15051"
private const val DEFAULT_KEY_ID = "zeta-guard-keycloak-tls-es256-v1.p256"
private const val ALIAS = "demo"

fun main(args: Array<String>) {
    val endpoint = args.option("--endpoint") ?: DEFAULT_ENDPOINT
    val keyId = args.option("--key-id") ?: DEFAULT_KEY_ID

    println("HSM Proxy Provider Example")
    println("  endpoint : $endpoint")
    println("  key-id   : $keyId")
    println()

    // 1. Register the provider with the JVM security framework
    val provider = HsmProxyProvider()
    Security.addProvider(provider)
    println("[1] Provider registered: ${provider.name}")

    // 2. Load the KeyStore — the certificate is fetched via GetCertificate RPC,
    //    no PEM file on disk required
    val config =
        """
        hsm.endpoint=$endpoint
        keys.$ALIAS.key_id=$keyId
        """.trimIndent()

    val keyStore =
        KeyStore.getInstance(HsmProxyProvider.KEYSTORE_TYPE).apply {
            load(config.byteInputStream(), null)
        }
    val cert = keyStore.getCertificate(ALIAS)
    println("[2] Certificate loaded: ${cert.toString().lines().first()}")

    // 3. Sign — delegates to hsm_sim via gRPC; private key never leaves the HSM
    val payload = "Hello, HSM!".toByteArray()
    val privateKey = keyStore.getKey(ALIAS, null) as PrivateKey

    val signer = Signature.getInstance(HsmProxyProvider.SIGNATURE_ALGORITHM, provider)
    signer.initSign(privateKey)
    signer.update(payload)
    val signature = signer.sign()
    println("[3] Signed ${payload.size} bytes → ${signature.size}-byte DER signature")

    // 4. Verify — uses the standard JVM provider with the public key from the certificate
    val verifier = Signature.getInstance(HsmProxyProvider.SIGNATURE_ALGORITHM)
    verifier.initVerify(cert)
    verifier.update(payload)
    val valid = verifier.verify(signature)
    println("[4] Signature valid: $valid")

    check(valid) { "Signature verification failed" }
    println()
    println("Success.")
}

private fun Array<String>.option(name: String): String? {
    val idx = indexOf(name)
    return if (idx >= 0 && idx + 1 < size) get(idx + 1) else null
}
