package com.authcore.auth.event.listener;

import java.util.Map;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.authcore.auth.dto.MailBody;
import com.authcore.auth.event.DeleteAccountEvent;
import com.authcore.auth.service.EmailService;
import com.authcore.auth.utils.impl.TokenEmailMessageBodyBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class DeleteAccountEventListner implements ApplicationListener<DeleteAccountEvent> {
    private final EmailService emailService;
    private final TokenEmailMessageBodyBuilder msgBuilder;

    @Override
    public void onApplicationEvent(@NonNull DeleteAccountEvent event) {
        msgBuilder.setTemplateName("delete_account_email");
        Map<String, String> data = event.getDeleteAccountDTO().getAllData();
        String htmlTemplate = msgBuilder.getMessage(data);

        MailBody mailBody = new MailBody(data.get("email"), "Delete Account",
                htmlTemplate);
        try {
            emailService.sendEmail(mailBody);
        } catch (Exception e) {
            log.error("Error sending email: " + e.getMessage());
        }
    }

}
