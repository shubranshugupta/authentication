package com.portfoliopro.auth.event.listener;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.portfoliopro.auth.dto.MailBody;
import com.portfoliopro.auth.event.PasswordResetEvent;
import com.portfoliopro.auth.service.EmailService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class PasswordResetEventListener implements ApplicationListener<PasswordResetEvent> {
    private final EmailService emailService;
    private final TemplateEngine templateEngine;

    @Override
    public void onApplicationEvent(@NonNull PasswordResetEvent event) {
        String email = event.getPasswordResetDTO().getEmail();
        String firstName = event.getPasswordResetDTO().getFirstName();
        String lastName = event.getPasswordResetDTO().getLastName();
        String otp = event.getPasswordResetDTO().getToken();
        String baseUrl = event.getPasswordResetDTO().getBaseUrl();

        Context context = new Context();
        context.setVariable("title", "Welcome to PortfolioPro");
        context.setVariable("firstName", StringUtils.capitalize(firstName));
        context.setVariable("lastName", StringUtils.capitalize(lastName));
        context.setVariable("otp", otp);
        context.setVariable("baseUrl", baseUrl);

        String htmlTemplate = templateEngine.process("password_reset_email", context);

        MailBody mailBody = new MailBody(email, "Password Reset",
                htmlTemplate);
        try {
            emailService.sendEmail(mailBody);
        } catch (Exception e) {
            log.error("Error sending email: " + e.getMessage());
        }
    }
}
