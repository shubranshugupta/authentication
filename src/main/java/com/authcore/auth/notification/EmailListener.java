package com.authcore.auth.notification;

import java.io.UnsupportedEncodingException;
import java.time.Duration;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.retry.RetryException;
import org.springframework.core.retry.RetryPolicy;
import org.springframework.core.retry.RetryTemplate;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.authcore.auth.common.AuthConfigProperties;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Renders and sends every email. Runs on the email threads, so requests don't wait for
 * the mail server, and only after the transaction that asked for the email committed.
 *
 * <p>Nobody is waiting for the result, so failures are handled here (H5): a few more tries
 * for a mail server that is down for a moment, then an error in the log. There is no
 * outbox table to send from later, because it would hold codes in plain text (C1); the
 * user can ask for a new email after a minute instead.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class EmailListener {
    /** 3 tries: at once, after 1 second, and 3 seconds after that. */
    private static final RetryTemplate RETRY = new RetryTemplate(RetryPolicy.builder()
            .maxRetries(2).delay(Duration.ofSeconds(1)).multiplier(3)
            .includes(MailSendException.class).build());

    private final TemplateEngine templateEngine;
    private final JavaMailSender mailSender;
    private final AuthConfigProperties authConfigProperties;

    // fallbackExecution: without a transaction, send it now. By default it would be ignored.
    @Async(EmailConfig.EMAIL_EXECUTOR)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void on(EmailRequested email) {
        try {
            MimeMessage message = message(email);
            RETRY.execute(() -> {
                mailSender.send(message);
                return null;
            });
        } catch (RetryException e) {
            logFailure(email, e.getCause());
        } catch (Exception e) {
            logFailure(email, e);
        }
    }

    private MimeMessage message(EmailRequested email) throws MessagingException, UnsupportedEncodingException {
        // The template name stays local. It used to be a field shared by every request,
        // so overlapping requests could send each other's email (C4).
        String html = templateEngine.process(email.template(), new Context(null, email.vars()));

        AuthConfigProperties.MailConfigProperties sender = authConfigProperties.getMail();
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        helper.setTo(email.to());
        helper.setFrom(sender.getFrom(), sender.getFromName());
        helper.setSubject(email.subject());
        helper.setText(html, true);
        helper.addInline("authcoreLogo", new ClassPathResource("static/logo_300.png"));
        return message;
    }

    /** Never the variables: they hold codes and links (H2). */
    private static void logFailure(EmailRequested email, Throwable e) {
        log.error("Email {} could not be sent", email.template(), e);
    }
}
