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
@file:Suppress("unused")

package de.gematik.zetaguard.hsmproxy

import java.io.File
import java.time.Duration
import org.slf4j.LoggerFactory
import org.testcontainers.containers.ComposeContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait

private const val SERVICE_NAME = "hsm-sim"
private const val GRPC_PORT = 50051

/**
 * Manages the hsm_sim Docker container for integration tests via [ComposeContainer].
 *
 * Started/stopped explicitly in test lifecycle (`beforeSpec` / `afterSpec`). Idempotent: calling [start] or [stop] multiple times is safe.
 */
object HsmSim {
  private var running = false

  private val log = LoggerFactory.getLogger(this.javaClass)

  private val compose: ComposeContainer =
      ComposeContainer(File("./docker-compose-it.yml"))
          .withLogConsumer(SERVICE_NAME, Slf4jLogConsumer(log).withMdc("container", SERVICE_NAME))
          .withExposedService(SERVICE_NAME, GRPC_PORT, Wait.forListeningPort().withStartupTimeout(Duration.ofSeconds(60)))
          .withPull(true)

  val host: String by lazy { if (running) compose.getServiceHost(SERVICE_NAME, GRPC_PORT) else "localhost" }
  val port: Int by lazy { if (running) compose.getServicePort(SERVICE_NAME, GRPC_PORT) else GRPC_PORT }
  val endpoint: String by lazy { "$host:$port" }

  fun start() {
    if (!running) {
      log.info("Starting hsm-sim via Docker Compose...")
      compose.start()
      running = true
    }
  }

  fun stop() {
    if (running) {
      log.info("Stopping hsm-sim...")
      compose.stop()
      running = false
    }
  }
}
