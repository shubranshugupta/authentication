package com.authcore.auth.notification;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import com.authcore.auth.common.AuthConfigProperties;

import lombok.extern.slf4j.Slf4j;

/**
 * Checks that a message really comes from SNS, the way AWS documents it: its signing
 * certificate is SNS's (by its URL), and the signature over the message's fields is right
 * (SignatureVersion 1: SHA1withRSA; 2: SHA256withRSA).
 */
@Slf4j
@Component
class SnsMessageVerifier {
    private static final List<String> NOTIFICATION_FIELDS = List.of("Message", "MessageId", "Subject", "Timestamp",
            "TopicArn", "Type");
    private static final List<String> SUBSCRIPTION_FIELDS = List.of("Message", "MessageId", "SubscribeURL",
            "Timestamp", "Token", "TopicArn", "Type");

    private final SnsCertificates certificates;
    private final Pattern certificateUrl;

    SnsMessageVerifier(SnsCertificates certificates, AuthConfigProperties properties) {
        this.certificates = certificates;
        this.certificateUrl = Pattern.compile(properties.getMail().getSes().getSnsCertificateUrlPattern());
    }

    /** Whether the certificate URL is SNS's: also used for the subscription link. */
    boolean isSnsUrl(String url) {
        return url != null && certificateUrl.matcher(url).matches();
    }

    boolean isGenuine(Map<String, String> message) {
        String certificate = message.get("SigningCertURL");
        if (!isSnsUrl(certificate)) {
            log.warn("SNS message refused: its certificate isn't from SNS");
            return false;
        }
        String algorithm = switch (String.valueOf(message.get("SignatureVersion"))) {
            case "1" -> "SHA1withRSA";
            case "2" -> "SHA256withRSA";
            default -> null;
        };
        String signature = message.get("Signature");
        if (algorithm == null || signature == null)
            return false;
        try {
            Signature check = Signature.getInstance(algorithm);
            check.initVerify(certificates.publicKey(URI.create(certificate)));
            check.update(stringToSign(message).getBytes(UTF_8));
            return check.verify(Base64.getDecoder().decode(signature));
        } catch (GeneralSecurityException | IllegalArgumentException | IllegalStateException e) {
            log.warn("SNS message refused: {}", e.getMessage());
            return false;
        }
    }

    /** Each field's name and value on lines of their own, in this order; a missing one is left out. */
    static String stringToSign(Map<String, String> message) {
        String type = message.get("Type");
        List<String> fields = "Notification".equals(type) ? NOTIFICATION_FIELDS : SUBSCRIPTION_FIELDS;
        StringBuilder text = new StringBuilder();
        for (String field : fields) {
            String value = message.get(field);
            if (value != null)
                text.append(field).append('\n').append(value).append('\n');
        }
        return text.toString();
    }
}
