package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.authcore.auth.support.TestcontainersConfiguration;

/**
 * F2: health checks and metrics, on a port of their own. A real server (not MockMvc), so
 * that both ports exist.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT, properties = "management.server.port=0")
@ActiveProfiles("test")
@AutoConfigureMetrics
@Import(TestcontainersConfiguration.class)
class ActuatorTests {
    private final HttpClient http = HttpClient.newHttpClient();

    @LocalServerPort
    private int apiPort;

    @LocalManagementPort
    private int managementPort;

    @Autowired
    private HealthEndpointGroups healthGroups;

    /** Like in IntegrationTest: the test profile has no mail server. */
    @MockitoBean
    private JavaMailSender mailSender;

    @Test
    void livenessAndReadinessAreUpOnTheManagementPort() throws Exception {
        assertThat(get(managementPort, "/actuator/health/liveness")).satisfies(response -> {
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).contains("\"status\":\"UP\"");
        });
        assertThat(get(managementPort, "/actuator/health/readiness").statusCode()).isEqualTo(200);
    }

    /** Without Redis the app still works (no rate limits): it must stay in service. */
    @Test
    void readinessNeedsTheDatabaseButNotRedis() {
        assertThat(healthGroups.get("readiness").isMember("db")).isTrue();
        assertThat(healthGroups.get("readiness").isMember("redis")).isFalse();
        assertThat(healthGroups.get("liveness").isMember("db")).isFalse();
    }

    @Test
    void healthNamesItsPartsButNoDetails() throws Exception {
        String body = get(managementPort, "/actuator/health").body();

        assertThat(body).contains("\"db\"", "\"redis\"");
        assertThat(body).doesNotContain("MySQL", "version", "database\"");
    }

    @Test
    void prometheusHasTheAppsMetrics() throws Exception {
        HttpResponse<String> response = get(managementPort, "/actuator/prometheus");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains(
                "authcore_rate_limit_redis_failures_total",
                "hikaricp_connections_max",
                "jvm_memory_used_bytes");
    }

    /** The API port is public; nothing of Actuator may be reachable there. */
    @Test
    void theApiPortHasNoActuator() throws Exception {
        for (String path : new String[] { "/actuator/health", "/actuator/prometheus", "/actuator" }) {
            HttpResponse<String> response = get(apiPort, path);
            assertThat(response.statusCode()).isIn(401, 404);
            assertThat(response.body()).doesNotContain("\"UP\"", "jvm_");
        }
    }

    private HttpResponse<String> get(int port, String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
