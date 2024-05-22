package com.portfoliopro.auth.event.listener;

import java.util.Map;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.portfoliopro.auth.dto.MailBody;
import com.portfoliopro.auth.event.RegistrationCompletionEvent;
import com.portfoliopro.auth.service.EmailService;
import com.portfoliopro.auth.utils.impl.TokenEmailMessageBodyBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompletionEventListener implements ApplicationListener<RegistrationCompletionEvent> {
    private final EmailService emailService;
    private final TokenEmailMessageBodyBuilder msgBuilder;

    @Override
    public void onApplicationEvent(@NonNull RegistrationCompletionEvent event) {
        Map<String, String> data = event.getTokenEmailDTO().getAllData();
        msgBuilder.setTemplateName("verify_registration_email");
        String htmlTemplate = msgBuilder.getMessage(data);

        MailBody mailBody = new MailBody(data.get("email"), "Verify Email",
                htmlTemplate);
        try {
            emailService.sendEmail(mailBody);
        } catch (Exception e) {
            log.error("Error sending email: " + e.getMessage());
        }
    }

}
