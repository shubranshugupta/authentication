package com.authcore.auth.service;

import java.io.UnsupportedEncodingException;

import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.core.io.ClassPathResource;

import com.authcore.auth.config.properties.AuthConfigProperties;
import com.authcore.auth.dto.MailBody;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender javaMailSender;
    private final AuthConfigProperties authConfigProperties;

    @Async
    public void sendEmail(MailBody mailBody) throws MessagingException, UnsupportedEncodingException {
        AuthConfigProperties.MailConfigProperties sender = authConfigProperties.getMail();
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper msgHelper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

        msgHelper.setTo(mailBody.getTo());
        msgHelper.setFrom(sender.getFrom(), sender.getFromName());
        msgHelper.setSubject(mailBody.getSubject());
        msgHelper.setText(mailBody.getText(), true);
        msgHelper.addInline("authcoreLogo", new ClassPathResource("static/logo_300.png"));

        javaMailSender.send(mimeMessage);
    }
}
