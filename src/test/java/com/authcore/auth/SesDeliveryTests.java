package com.authcore.auth;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.authcore.auth.support.TestcontainersConfiguration;
import com.jayway.jsonpath.JsonPath;
import com.sun.net.httpserver.HttpServer;

/**
 * M7e: with MAIL_TRANSPORT=ses the whole application sends through the SES v2 API. A local
 * server stands in for SES and keeps what it gets. Unlike the other tests, JavaMailSender
 * isn't mocked here.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration.class)
class SesDeliveryTests {
    private static final List<String> RECEIVED = new CopyOnWriteArrayList<>();
    private static final HttpServer SES = fakeSes();

    @DynamicPropertySource
    static void sesProperties(DynamicPropertyRegistry registry) {
        registry.add("auth.mail.transport", () -> "ses");
        registry.add("auth.mail.ses.region", () -> "eu-west-1");
        registry.add("auth.mail.ses.endpoint", () -> "http://127.0.0.1:" + SES.getAddress().getPort());
        registry.add("auth.mail.ses.configuration-set", () -> "authcore-test");
        // The SDK reads these from the environment, or from system properties like here.
        System.setProperty("aws.accessKeyId", "test");
        System.setProperty("aws.secretAccessKey", "test");
    }

    @Autowired
    private MockMvc mvc;
    @Autowired
    private JavaMailSender mailSender;

    @Test
    void theSesSenderReplacesSmtp() {
        assertThat(mailSender.getClass().getSimpleName()).isEqualTo("SesMailSender");
    }

    @Test
    void aVerificationEmailGoesThroughTheSesApi() throws Exception {
        String email = "user-" + UUID.randomUUID() + "@example.com";

        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"firstName\": \"Jane\", \"email\": \"%s\", \"password\": \"Str0ng-Passw0rd!\"}".formatted(email)))
                .andExpect(status().isOk());

        Awaitility.await().atMost(Duration.ofSeconds(10))
                .until(() -> RECEIVED.stream().anyMatch(r -> raw(r).contains(email)));
        String request = RECEIVED.stream().filter(r -> raw(r).contains(email)).findFirst().orElseThrow();
        assertThat((String) JsonPath.read(request, "$.ConfigurationSetName")).isEqualTo("authcore-test");
        assertThat(raw(request)).contains("To: " + email, "Subject: Verify Email", "verify-email?token=",
                "Content-ID: <authcoreLogo>");
    }

    /** The request held the whole message, base64; recipients are read from it. */
    private static String raw(String request) {
        return new String(Base64.getMimeDecoder().decode((String) JsonPath.read(request, "$.Content.Raw.Data")), UTF_8);
    }

    private static HttpServer fakeSes() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/v2/email/outbound-emails", exchange -> {
                RECEIVED.add(new String(exchange.getRequestBody().readAllBytes(), UTF_8));
                byte[] answer = "{\"MessageId\":\"ses-1\"}".getBytes(UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, answer.length);
                exchange.getResponseBody().write(answer);
                exchange.close();
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
