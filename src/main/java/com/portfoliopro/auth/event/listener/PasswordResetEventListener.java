package com.portfoliopro.auth.event.listener;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.portfoliopro.auth.dto.MailBody;
import com.portfoliopro.auth.entities.Otp;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.event.PasswordResetEvent;
import com.portfoliopro.auth.service.EmailService;
import com.portfoliopro.auth.service.PasswordResetService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class PasswordResetEventListener implements ApplicationListener<PasswordResetEvent> {
    private final PasswordResetService passwordResetService;
    private final EmailService emailService;
    private final TemplateEngine templateEngine;

    @Override
    public void onApplicationEvent(@NonNull PasswordResetEvent event) {
        User user = event.getUser();
        Otp otp = passwordResetService.createOtp(user);
        if (otp.equals(user.getOtp())) {
            return;
        }

        Context context = new Context();
        context.setVariable("firstName", StringUtils.capitalize(user.getFirstName()));
        context.setVariable("lastName", StringUtils.capitalize(user.getLastName()));
        context.setVariable("otp", otp.getOtp());

        String htmlTemplate = templateEngine.process("password_reset_email", context);

        MailBody mailBody = new MailBody(user.getEmail(), "Password Reset",
                htmlTemplate);
        try {
            emailService.sendEmail(mailBody);
        } catch (Exception e) {
            log.error("Error sending email: " + e.getMessage());
        }
    }
}
