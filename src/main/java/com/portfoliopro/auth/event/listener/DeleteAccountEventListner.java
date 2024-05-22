package com.portfoliopro.auth.event.listener;

import java.util.Map;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.portfoliopro.auth.dto.MailBody;
import com.portfoliopro.auth.event.DeleteAccountEvent;
import com.portfoliopro.auth.service.EmailService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class DeleteAccountEventListner implements ApplicationListener<DeleteAccountEvent> {
    private final EmailService emailService;
    private final TemplateEngine templateEngine;

    @Override
    public void onApplicationEvent(@NonNull DeleteAccountEvent event) {
        Map<String, String> data = event.getDeleteAccountDTO().getAllData();
        String email = data.get("email");
        String firstName = data.get("firstName");
        String lastName = data.get("lastName");
        String otp = data.get("token");
        String baseUrl = data.get("baseUrl");

        Context context = new Context();
        context.setVariable("title", "Welcome to PortfolioPro");
        context.setVariable("firstName", StringUtils.capitalize(firstName));
        context.setVariable("lastName", StringUtils.capitalize(lastName));
        context.setVariable("otp", otp);
        context.setVariable("baseUrl", baseUrl);

        String htmlTemplate = templateEngine.process("delete_account_email", context);

        MailBody mailBody = new MailBody(email, "Delete Account",
                htmlTemplate);
        try {
            emailService.sendEmail(mailBody);
        } catch (Exception e) {
            log.error("Error sending email: " + e.getMessage());
        }
    }

}
