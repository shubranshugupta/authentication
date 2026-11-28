package com.authcore.auth.notification;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mail.MailPreparationException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.MimeMessageHelper;

import com.jayway.jsonpath.JsonPath;
import com.sun.net.httpserver.HttpServer;

import jakarta.mail.internet.MimeMessage;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;

/** M7e: the email goes to SES's API as the raw MIME message, and SES's errors are sorted out. */
class SesMailSenderTests {
    private HttpServer ses;
    private final List<String> requests = new ArrayList<>();
    private final List<String> paths = new ArrayList<>();
    private volatile int status = 200;
    private volatile String errorType;

    @BeforeEach
    void startFakeSes() throws Exception {
        ses = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        ses.createContext("/", exchange -> {
            paths.add(exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath());
            requests.add(new String(exchange.getRequestBody().readAllBytes(), UTF_8));
            byte[] body = (status == 200 ? "{\"MessageId\":\"ses-message-1\"}" : "{\"message\":\"no\"}").getBytes(UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            if (errorType != null)
                exchange.getResponseHeaders().add("x-amzn-ErrorType", errorType);
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        ses.start();
    }

    @AfterEach
    void stopFakeSes() {
        ses.stop(0);
    }

    @Test
    void theEmailIsSentAsItIsWithTheConfigurationSet() throws Exception {
        sender("authcore-events").send(message());

        assertThat(paths).containsExactly("POST /v2/email/outbound-emails");
        String request = requests.getFirst();
        assertThat((String) JsonPath.read(request, "$.ConfigurationSetName")).isEqualTo("authcore-events");
        String raw = new String(Base64.getDecoder().decode((String) JsonPath.read(request, "$.Content.Raw.Data")), UTF_8);
        assertThat(raw).contains("To: jane@example.com", "From: AuthCore <noreply@authcore.test>",
                "Subject: Password Reset", "the code is 12345678");
    }

    @Test
    void withoutAConfigurationSetNoneIsNamed() throws Exception {
        sender(" ").send(message());

        assertThat(requests.getFirst()).doesNotContain("ConfigurationSetName");
    }

    @Test
    void tooManyRequestsAndSesFailuresAreTriedAgain() throws Exception {
        status = 429;
        errorType = "TooManyRequestsException";
        assertThatThrownBy(() -> sender(null).send(message())).isInstanceOf(MailSendException.class)
                .hasMessageContaining("TooManyRequestsException");

        status = 500;
        errorType = "InternalFailure";
        assertThatThrownBy(() -> sender(null).send(message())).isInstanceOf(MailSendException.class);
    }

    @Test
    void aRejectedEmailIsNotTriedAgain() throws Exception {
        status = 400;
        errorType = "MessageRejected";

        assertThatThrownBy(() -> sender(null).send(message()))
                .isInstanceOf(MailPreparationException.class)
                .isNotInstanceOf(MailSendException.class)
                .hasMessageContaining("MessageRejected");
    }

    @Test
    void sesOutOfReachIsTriedAgain() throws Exception {
        SesMailSender sender = sender(null);
        ses.stop(0);

        assertThatThrownBy(() -> sender.send(message())).isInstanceOf(MailSendException.class)
                .hasMessageContaining("could not be reached");
    }

    private MimeMessage message() throws Exception {
        MimeMessage message = sender(null).createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setTo("jane@example.com");
        helper.setFrom("noreply@authcore.test", "AuthCore");
        helper.setSubject("Password Reset");
        helper.setText("<p>the code is 12345678</p>", true);
        return message;
    }

    private SesMailSender sender(String configurationSet) {
        SesV2Client client = SesV2Client.builder()
                .region(Region.EU_WEST_1)
                .endpointOverride(URI.create("http://127.0.0.1:" + ses.getAddress().getPort()))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                // EmailListener tries again itself; here each answer counts once.
                .overrideConfiguration(config -> config.retryStrategy(AwsRetryStrategy.doNotRetry()))
                .build();
        return new SesMailSender(client, configurationSet);
    }
}
