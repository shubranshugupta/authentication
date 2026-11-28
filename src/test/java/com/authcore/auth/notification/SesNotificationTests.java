package com.authcore.auth.notification;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.ResultActions;

import com.authcore.auth.support.IntegrationTest;
import com.authcore.auth.user.admin.AdminBootstrap;
import com.sun.net.httpserver.HttpServer;

import io.micrometer.core.instrument.MeterRegistry;
import tools.jackson.databind.json.JsonMapper;

/**
 * M7e: SES's bounce and complaint notifications, delivered by SNS, fill the suppression
 * list, and suppressed addresses aren't emailed. The messages are signed here like SNS
 * signs them, with a test key; a local server stands in for SNS's subscription link.
 */
@ExtendWith(OutputCaptureExtension.class)
class SesNotificationTests extends IntegrationTest {
    private static final String TOPIC = "arn:aws:sns:eu-west-1:123456789012:authcore-ses";
    private static final KeyPair SNS_KEY = keyPair();
    private static final KeyPair OTHER_KEY = keyPair();
    private static final List<String> CONFIRMED = new CopyOnWriteArrayList<>();
    private static final HttpServer SNS = server();

    @DynamicPropertySource
    static void sesProperties(DynamicPropertyRegistry registry) {
        registry.add("auth.mail.ses.topic-arn", () -> TOPIC);
        // The local stand-in for SNS's host.
        registry.add("auth.mail.ses.sns-certificate-url-pattern", () -> "http://127\\.0\\.0\\.1:\\d+/[^?#]+\\.pem");
    }

    @MockitoBean
    private SnsCertificates certificates;
    @Autowired
    private AdminBootstrap adminBootstrap;
    @Autowired
    private MeterRegistry meters;

    private final JsonMapper json = JsonMapper.builder().build();

    @BeforeEach
    void snsSignsWithItsKey() {
        when(certificates.publicKey(any())).thenReturn(SNS_KEY.getPublic());
    }

    // ---- bounces and complaints ----------------------------------------------------------

    @Test
    void aPermanentBounceStopsEmailsToTheAddress() throws Exception {
        String email = uniqueEmail();

        deliver(notification(bounce("Permanent", "General", email))).andExpect(status().isOk());

        register(email, PASSWORD).andExpect(status().isOk());
        assertNoEmail(email, "Verify Email");
        assertThat(meters.counter("authcore.emails", "template", "verify_registration_email", "outcome", "suppressed")
                .count()).isPositive();
        assertThat(jdbc.queryForMap("select reason, detail from email_suppressions where email = ?", email))
                .containsEntry("reason", "BOUNCE").containsEntry("detail", "General");
    }

    @Test
    void aTransientBounceDoesNot() throws Exception {
        String email = uniqueEmail();

        deliver(notification(bounce("Transient", "MailboxFull", email))).andExpect(status().isOk());

        register(email, PASSWORD).andExpect(status().isOk());
        awaitEmail(email, "Verify Email");
    }

    @Test
    void aComplaintStopsEmailsToo() throws Exception {
        String email = uniqueEmail();
        Map<String, Object> complaint = Map.of("notificationType", "Complaint", "complaint",
                Map.of("complaintFeedbackType", "abuse", "complainedRecipients",
                        List.of(Map.of("emailAddress", "Jane Doe <" + email.toUpperCase() + ">"))));

        deliver(notification(complaint)).andExpect(status().isOk());

        assertThat(jdbc.queryForMap("select reason, detail from email_suppressions where email = ?", email))
                .containsEntry("reason", "COMPLAINT").containsEntry("detail", "abuse");
    }

    @Test
    void theSameNotificationTwiceIsHarmless() throws Exception {
        String email = uniqueEmail();
        Map<String, String> message = notification(bounce("Permanent", "General", email));

        deliver(message).andExpect(status().isOk());
        deliver(message).andExpect(status().isOk());

        assertThat(jdbc.queryForObject("select count(*) from email_suppressions where email = ?", Integer.class, email))
                .isOne();
    }

    @Test
    void otherEventsAreIgnored() throws Exception {
        String email = uniqueEmail();

        deliver(notification(Map.of("eventType", "Delivery", "delivery",
                Map.of("recipients", List.of(email))))).andExpect(status().isOk());

        assertThat(jdbc.queryForObject("select count(*) from email_suppressions where email = ?", Integer.class, email))
                .isZero();
    }

    @Test
    void theSuppressionIsAuditedWithoutTheAddress(CapturedOutput output) throws Exception {
        String email = uniqueEmail();
        registerVerifiedUserAndLogin(email);

        deliver(notification(bounce("Permanent", "General", email))).andExpect(status().isOk());

        assertThat(output.getAll().lines().filter(line -> line.contains(" AUDIT ")))
                .anyMatch(line -> line.contains("EMAIL_SUPPRESSED userId=" + user(email).getId())
                        && line.contains("reason=BOUNCE"))
                .noneMatch(line -> line.contains(email));
    }

    // ---- only SNS, only our topic ---------------------------------------------------------

    @Test
    void aWrongSignatureIsRefused() throws Exception {
        String email = uniqueEmail();
        Map<String, String> message = notification(bounce("Permanent", "General", email));
        sign(message, OTHER_KEY, "2");

        deliver(message).andExpect(status().isForbidden());
        assertNotSuppressed(email);
    }

    @Test
    void aChangedMessageIsRefused() throws Exception {
        String email = uniqueEmail();
        Map<String, String> message = notification(bounce("Permanent", "General", uniqueEmail()));
        message.put("Message", json.writeValueAsString(bounce("Permanent", "General", email)));

        deliver(message).andExpect(status().isForbidden());
        assertNotSuppressed(email);
    }

    @Test
    void anotherTopicIsRefused() throws Exception {
        String email = uniqueEmail();
        Map<String, String> message = notification(bounce("Permanent", "General", email));
        message.put("TopicArn", "arn:aws:sns:eu-west-1:999999999999:someone-else");
        sign(message, SNS_KEY, "2");

        deliver(message).andExpect(status().isForbidden());
        assertNotSuppressed(email);
    }

    @Test
    void aCertificateFromElsewhereIsRefused() throws Exception {
        String email = uniqueEmail();
        Map<String, String> message = notification(bounce("Permanent", "General", email));
        message.put("SigningCertURL", "https://attacker.example.com/cert.pem");
        sign(message, SNS_KEY, "2");

        deliver(message).andExpect(status().isForbidden());
        assertNotSuppressed(email);
    }

    @Test
    void signatureVersion1IsAcceptedToo() throws Exception {
        String email = uniqueEmail();
        Map<String, String> message = notification(bounce("Permanent", "General", email));
        sign(message, SNS_KEY, "1");

        deliver(message).andExpect(status().isOk());
        assertThat(jdbc.queryForObject("select count(*) from email_suppressions where email = ?", Integer.class, email))
                .isOne();
    }

    @Test
    void notJsonIsRefused() throws Exception {
        mvc.perform(post("/api/v1/webhooks/ses").contentType(MediaType.TEXT_PLAIN).content("hello"))
                .andExpect(status().isForbidden());
    }

    // ---- the subscription -----------------------------------------------------------------

    @Test
    void aSubscriptionIsConfirmedOnSnsHost() throws Exception {
        String token = UUID.randomUUID().toString();
        Map<String, String> message = envelope("SubscriptionConfirmation", "You have chosen to subscribe");
        message.put("Token", token);
        message.put("SubscribeURL", snsUrl("/?Action=ConfirmSubscription&Token=" + token));
        sign(message, SNS_KEY, "1");

        deliver(message).andExpect(status().isOk());

        assertThat(CONFIRMED).anyMatch(uri -> uri.contains(token));
    }

    @Test
    void aSubscriptionLinkElsewhereIsNotFollowed() throws Exception {
        String token = UUID.randomUUID().toString();
        Map<String, String> message = envelope("SubscriptionConfirmation", "You have chosen to subscribe");
        message.put("Token", token);
        message.put("SubscribeURL", "http://localhost:" + SNS.getAddress().getPort() + "/?Token=" + token);
        sign(message, SNS_KEY, "1");

        deliver(message).andExpect(status().isOk());

        Thread.sleep(300);
        assertThat(CONFIRMED).noneMatch(uri -> uri.contains(token));
    }

    // ---- admins ------------------------------------------------------------------------------

    @Test
    void adminsSeeTheListAndCanTakeAnAddressOff() throws Exception {
        String adminEmail = uniqueEmail();
        String admin = registerVerifiedUserAndLogin(adminEmail);
        adminBootstrap.promote(List.of(adminEmail));
        String email = uniqueEmail();
        deliver(notification(bounce("Permanent", "General", email))).andExpect(status().isOk());

        mvc.perform(as(admin, get("/api/v1/admin/email-suppressions").param("size", "100")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[?(@.email == '" + email + "')].reason").value("BOUNCE"));
        removeAs(admin, email, "Wrong-passw0rd!").andExpect(status().isForbidden());
        removeAs(admin, email, PASSWORD).andExpect(jsonPath("$.msg").value("Taken off the suppression list."));
        removeAs(admin, email, PASSWORD).andExpect(jsonPath("$.msg").value("It wasn't on the suppression list."));

        register(email, PASSWORD).andExpect(status().isOk());
        awaitEmail(email, "Verify Email");
    }

    @Test
    void usersCannotSeeOrChangeTheList() throws Exception {
        String accessToken = registerVerifiedUserAndLogin(uniqueEmail());

        mvc.perform(as(accessToken, get("/api/v1/admin/email-suppressions"))).andExpect(status().isForbidden());
        removeAs(accessToken, uniqueEmail(), PASSWORD).andExpect(status().isForbidden());
    }

    // ---- helpers -----------------------------------------------------------------------------

    private ResultActions deliver(Map<String, String> message) throws Exception {
        // SNS sends JSON as text/plain.
        return mvc.perform(post("/api/v1/webhooks/ses").contentType(MediaType.TEXT_PLAIN)
                .content(json.writeValueAsString(message)));
    }

    private ResultActions removeAs(String accessToken, String email, String password) throws Exception {
        return mvc.perform(as(accessToken, post("/api/v1/admin/email-suppressions/remove"))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\": \"%s\", \"password\": \"%s\"}".formatted(email, password)));
    }

    private static Map<String, Object> bounce(String type, String subType, String email) {
        return Map.of("eventType", "Bounce", "bounce", Map.of("bounceType", type, "bounceSubType", subType,
                "bouncedRecipients", List.of(Map.of("emailAddress", email))));
    }

    private Map<String, String> notification(Map<String, Object> event) {
        Map<String, String> message = envelope("Notification", json.writeValueAsString(event));
        sign(message, SNS_KEY, "2");
        return message;
    }

    private static Map<String, String> envelope(String type, String text) {
        Map<String, String> message = new LinkedHashMap<>();
        message.put("Type", type);
        message.put("MessageId", UUID.randomUUID().toString());
        message.put("TopicArn", TOPIC);
        message.put("Message", text);
        message.put("Timestamp", "2026-11-28T10:00:00.000Z");
        message.put("SigningCertURL", snsUrl("/SimpleNotificationService-test.pem"));
        return message;
    }

    /** As AWS documents it: each field's name and value on lines of their own, in this order. */
    private static void sign(Map<String, String> message, KeyPair key, String version) {
        List<String> fields = "Notification".equals(message.get("Type"))
                ? List.of("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type")
                : List.of("Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type");
        StringBuilder text = new StringBuilder();
        for (String field : fields)
            if (message.containsKey(field))
                text.append(field).append('\n').append(message.get(field)).append('\n');
        try {
            Signature signature = Signature.getInstance("1".equals(version) ? "SHA1withRSA" : "SHA256withRSA");
            signature.initSign(key.getPrivate());
            signature.update(text.toString().getBytes(UTF_8));
            message.put("SignatureVersion", version);
            message.put("Signature", Base64.getEncoder().encodeToString(signature.sign()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String snsUrl(String path) {
        return "http://127.0.0.1:" + SNS.getAddress().getPort() + path;
    }

    private void assertNotSuppressed(String email) {
        assertThat(jdbc.queryForObject("select count(*) from email_suppressions where email = ?", Integer.class, email))
                .isZero();
    }

    private void assertNoEmail(String to, String subject) throws Exception {
        Thread.sleep(700);
        assertThat(sentEmails(to, subject)).isEmpty();
    }

    private static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Records the subscription links that were followed. */
    private static HttpServer server() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                CONFIRMED.add(exchange.getRequestURI().toString());
                exchange.sendResponseHeaders(200, -1);
                exchange.close();
            });
            server.start();
            return server;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
