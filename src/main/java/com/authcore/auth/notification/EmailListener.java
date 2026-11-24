package com.authcore.auth.notification;

import java.io.UnsupportedEncodingException;

import org.springframework.core.io.ClassPathResource;
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

/**
 * Renders and sends every email. Runs on the email threads, so requests don't wait for
 * the mail server, and only after the transaction that asked for the email committed.
 * (fallbackExecution: most callers have no transaction until H5, Phase 4.)
 */
@Component
@RequiredArgsConstructor
public class EmailListener {
    private final TemplateEngine templateEngine;
    private final JavaMailSender mailSender;
    private final AuthConfigProperties authConfigProperties;

    @Async(EmailConfig.EMAIL_EXECUTOR)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void on(EmailRequested email) throws MessagingException, UnsupportedEncodingException {
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
        mailSender.send(message);
    }
}
