package com.portfoliopro.auth.service;

import java.io.UnsupportedEncodingException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.dto.MailBody;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender javaMailSender;

    @Value("${spring.mail.username}")
    private String FROM_EMAIL;

    private static final String SENDER_NAME = "PortfolioPro";

    @Async
    public void sendEmail(MailBody mailBody) throws MessagingException, UnsupportedEncodingException {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper msgHelper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

        msgHelper.setTo(mailBody.getTo());
        msgHelper.setFrom(FROM_EMAIL, SENDER_NAME);
        msgHelper.setSubject(mailBody.getSubject());
        msgHelper.setText(mailBody.getText(), true);

        javaMailSender.send(mimeMessage);
    }
}