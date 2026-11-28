package com.authcore.auth.notification;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authcore.auth.common.AuthConfigProperties;

import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Where SNS delivers SES's bounce and complaint notifications (M7e). Only messages SNS
 * really signed, from the configured topic, are used: a permanent bounce or a complaint puts
 * the address on the suppression list. A new subscription is confirmed here too.
 *
 * <p>Off (404) while SES_SNS_TOPIC_ARN is empty. Public, like the logins: SNS can't log in;
 * its signature is the proof.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/webhooks/ses")
@RequiredArgsConstructor
@SecurityRequirements
@Tag(name = "Webhooks", description = "Notifications from AWS")
public class SesNotificationController {
    private final SnsMessageVerifier verifier;
    private final SuppressionList suppressionList;
    private final AuthConfigProperties properties;
    private final JsonMapper json = JsonMapper.builder().build();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    /** SNS sends {@code text/plain}, whatever the body is. */
    @PostMapping(consumes = "*/*")
    public ResponseEntity<Void> receive(@RequestBody String body) {
        String topic = properties.getMail().getSes().getTopicArn();
        if (!StringUtils.hasText(topic))
            return ResponseEntity.notFound().build();

        Map<String, String> message = parse(body);
        if (message == null || !topic.equals(message.get("TopicArn")) || !verifier.isGenuine(message)) {
            log.warn("SES notification refused: not from SNS, or from another topic");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        switch (String.valueOf(message.get("Type"))) {
            case "SubscriptionConfirmation" -> confirm(message);
            case "Notification" -> handle(message.get("Message"));
            default -> {
                // UnsubscribeConfirmation: nothing to do.
            }
        }
        return ResponseEntity.ok().build();
    }

    private Map<String, String> parse(String body) {
        try {
            JsonNode root = json.readTree(body);
            if (!root.isObject())
                return null;
            Map<String, String> fields = new HashMap<>();
            root.properties().forEach(field -> fields.put(field.getKey(), field.getValue().asString()));
            return fields;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The subscription link must be on SNS's own host, like the certificate. */
    private void confirm(Map<String, String> message) {
        URI link = URI.create(message.get("SubscribeURL"));
        URI certificate = URI.create(message.get("SigningCertURL"));
        if (!link.getScheme().equals(certificate.getScheme()) || !link.getHost().equals(certificate.getHost())
                || link.getPort() != certificate.getPort()) {
            log.warn("SNS subscription not confirmed: its link isn't on SNS's host");
            return;
        }
        try {
            int status = http.send(HttpRequest.newBuilder(link).timeout(Duration.ofSeconds(10)).GET().build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode();
            log.info("SNS subscription to {} confirmed ({})", message.get("TopicArn"), status);
        } catch (Exception e) {
            if (e instanceof InterruptedException)
                Thread.currentThread().interrupt();
            log.warn("SNS subscription could not be confirmed", e);
        }
    }

    /** SES's event: from a configuration set ("eventType") or an identity ("notificationType"). */
    private void handle(String text) {
        JsonNode event;
        try {
            event = json.readTree(text);
        } catch (RuntimeException e) {
            log.warn("SES notification ignored: its message isn't JSON");
            return;
        }
        String type = event.path("eventType").asString(event.path("notificationType").asString(""));
        switch (type) {
            case "Bounce" -> {
                JsonNode bounce = event.path("bounce");
                // Transient bounces (a full mailbox, a server down) may work next time.
                if (!"Permanent".equals(bounce.path("bounceType").asString()))
                    return;
                for (JsonNode recipient : bounce.path("bouncedRecipients"))
                    suppress(recipient, EmailSuppression.Reason.BOUNCE, bounce.path("bounceSubType").asString(null));
            }
            case "Complaint" -> {
                JsonNode complaint = event.path("complaint");
                for (JsonNode recipient : complaint.path("complainedRecipients"))
                    suppress(recipient, EmailSuppression.Reason.COMPLAINT,
                            complaint.path("complaintFeedbackType").asString(null));
            }
            default -> {
                // Deliveries, sends, opens...: not needed.
            }
        }
    }

    private void suppress(JsonNode recipient, EmailSuppression.Reason reason, String detail) {
        String address = recipient.path("emailAddress").asString("");
        try {
            // It may come as "Jane Doe <jane@example.com>".
            suppressionList.add(new InternetAddress(address, true).getAddress(), reason, detail);
        } catch (AddressException e) {
            log.warn("SES notification: a recipient that isn't an email address was ignored");
        }
    }
}
