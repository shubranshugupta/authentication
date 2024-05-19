package com.portfoliopro.auth.event.listener;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.portfoliopro.auth.dto.MailBody;
import com.portfoliopro.auth.event.RegistrationCompletionEvent;
import com.portfoliopro.auth.service.EmailService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompletionEventListener implements ApplicationListener<RegistrationCompletionEvent> {
    private final EmailService emailService;
    private final TemplateEngine templateEngine;

    @Override
    public void onApplicationEvent(@NonNull RegistrationCompletionEvent event) {
        String email = event.getTokenEmailDTO().getEmail();
        String firstName = event.getTokenEmailDTO().getFirstName();
        String lastName = event.getTokenEmailDTO().getLastName();
        String appUrl = event.getTokenEmailDTO().getToken();
        String baseUrl = event.getTokenEmailDTO().getBaseUrl();

        Context context = new Context();
        context.setVariable("title", "Welcome to PortfolioPro");
        context.setVariable("firstName", StringUtils.capitalize(firstName));
        context.setVariable("lastName", StringUtils.capitalize(lastName));
        context.setVariable("verifyUrl", appUrl);
        context.setVariable("baseUrl", baseUrl);

        String htmlTemplate = templateEngine.process("verify_registration_email", context);

        MailBody mailBody = new MailBody(email, "Verify Email",
                htmlTemplate);
        try {
            emailService.sendEmail(mailBody);
        } catch (Exception e) {
            log.error("Error sending email: " + e.getMessage());
        }
    }

}
