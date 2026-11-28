package com.authcore.auth.notification;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.jspecify.annotations.Nullable;
import org.springframework.mail.MailException;
import org.springframework.mail.MailPreparationException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.util.StringUtils;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.SendEmailRequest;
import software.amazon.awssdk.services.sesv2.model.SesV2Exception;

/**
 * Sends through the SES v2 API (MAIL_TRANSPORT=ses, M7e) instead of SMTP: over HTTPS, so no
 * SMTP port has to be open, and with a configuration set if one is given.
 *
 * <p>The email is built like for SMTP and sent as it is (a raw MIME message), so the
 * templates and the inline logo stay the same. Errors SES may get over by itself (too many
 * requests, its own failures, the network) are {@link MailSendException}s, which
 * EmailListener tries again; the others (a rejected email, an unverified sender) aren't.
 */
class SesMailSender extends JavaMailSenderImpl {
    private final SesV2Client ses;
    private final @Nullable String configurationSet;

    SesMailSender(SesV2Client ses, @Nullable String configurationSet) {
        this.ses = ses;
        this.configurationSet = StringUtils.hasText(configurationSet) ? configurationSet : null;
    }

    @Override
    protected void doSend(MimeMessage[] mimeMessages, Object @Nullable [] originalMessages) throws MailException {
        for (MimeMessage message : mimeMessages)
            send(raw(message));
    }

    private void send(byte[] raw) {
        try {
            ses.sendEmail(SendEmailRequest.builder()
                    .content(content -> content.raw(r -> r.data(SdkBytes.fromByteArray(raw))))
                    .configurationSetName(configurationSet)
                    .build());
        } catch (SesV2Exception e) {
            String code = e.awsErrorDetails() == null ? "unknown" : e.awsErrorDetails().errorCode();
            if (e.isThrottlingException() || e.statusCode() >= 500)
                throw new MailSendException("SES could not take the email for now: " + code, e);
            throw new MailPreparationException("SES refused the email: " + code, e);
        } catch (SdkClientException e) {
            // No answer from SES at all (network, DNS, a timeout).
            throw new MailSendException("SES could not be reached", e);
        }
    }

    private static byte[] raw(MimeMessage message) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            message.writeTo(bytes);
            return bytes.toByteArray();
        } catch (IOException | MessagingException e) {
            throw new MailPreparationException("The email could not be written", e);
        }
    }
}
