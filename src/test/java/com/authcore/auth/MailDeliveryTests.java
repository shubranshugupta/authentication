package com.authcore.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import com.authcore.auth.support.TestcontainersConfiguration;
import com.jayway.jsonpath.JsonPath;

/**
 * Real email delivery: the app sends over SMTP to a Mailpit container (the same fake
 * mail server docker-compose runs for development), and the test reads the inbox
 * through Mailpit's HTTP API. Unlike the other tests, JavaMailSender is not mocked,
 * so this runs in its own Spring context.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class MailDeliveryTests {
    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final long EMAIL_WAIT_MILLIS = 15_000;

    /** Started once for this class; Testcontainers removes it when the test JVM exits. */
    private static final GenericContainer<?> MAILPIT = new GenericContainer<>(DockerImageName.parse("axllent/mailpit:v1.27"))
            .withExposedPorts(1025, 8025)
            .withEnv("MP_SMTP_AUTH_ACCEPT_ANY", "1")
            .withEnv("MP_SMTP_AUTH_ALLOW_INSECURE", "1");

    static {
        MAILPIT.start();
    }

    // Registered before the context starts: Spring Boot only creates a JavaMailSender
    // when spring.mail.host is set at startup.
    @DynamicPropertySource
    static void mailServerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.mail.host", MAILPIT::getHost);
        registry.add("spring.mail.port", () -> MAILPIT.getMappedPort(1025));
        registry.add("spring.mail.username", () -> "test");
        registry.add("spring.mail.password", () -> "test");
    }

    @Autowired
    private MockMvc mvc;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void everyAppEmailIsDeliveredOverSmtpFromTheConfiguredSender() throws Exception {
        String email = "mail-" + UUID.randomUUID() + "@example.com";

        // Verification email
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content("""
                {"firstName": "jane", "lastName": "doe", "email": "%s", "password": "%s"}
                """.formatted(email, PASSWORD))).andExpect(status().isOk());
        Map<String, Object> verification = awaitMessage(email, "Verify Email");
        assertSentByAuthCore(verification);
        Matcher link = Pattern.compile("token=([A-Za-z0-9_-]{43})").matcher((String) verification.get("HTML"));
        assertThat(link.find()).isTrue();
        String token = link.group(1);

        // Password reset email
        mvc.perform(get("/auth/verify-email").param("email", email).param("token", token))
                .andExpect(status().isOk());
        mvc.perform(post("/auth/reset-password").param("email", email)).andExpect(status().isOk());
        assertSentByAuthCore(awaitMessage(email, "Password Reset"));

        // Account deletion email
        String body = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content("""
                {"email": "%s", "password": "%s"}
                """.formatted(email, PASSWORD)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String accessToken = JsonPath.read(body, "$.accessToken");
        mvc.perform(delete("/user/delete").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk());
        assertSentByAuthCore(awaitMessage(email, "Delete Account"));
    }

    private static void assertSentByAuthCore(Map<String, Object> message) {
        @SuppressWarnings("unchecked")
        Map<String, Object> from = (Map<String, Object>) message.get("From");
        assertThat(from.get("Address")).isEqualTo("noreply@authcore.test");
        assertThat(from.get("Name")).isEqualTo("AuthCore");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> inline = (List<Map<String, Object>>) message.get("Inline");
        assertThat(inline).extracting(part -> part.get("ContentID")).contains("authcoreLogo");
    }

    /** Polls Mailpit until a message with this subject arrives for this address. */
    private Map<String, Object> awaitMessage(String to, String subject) throws Exception {
        String api = "http://" + MAILPIT.getHost() + ":" + MAILPIT.getMappedPort(8025) + "/api/v1";
        String query = URLEncoder.encode("to:\"" + to + "\" subject:\"" + subject + "\"", StandardCharsets.UTF_8);
        long deadline = System.currentTimeMillis() + EMAIL_WAIT_MILLIS;
        while (System.currentTimeMillis() < deadline) {
            List<String> ids = JsonPath.read(fetch(api + "/search?query=" + query), "$.messages[*].ID");
            if (!ids.isEmpty())
                return JsonPath.read(fetch(api + "/message/" + ids.get(0)), "$");
            Thread.sleep(200);
        }
        return fail("No email '" + subject + "' reached Mailpit for " + to);
    }

    private String fetch(String url) throws Exception {
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(url)).build(),
                HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
