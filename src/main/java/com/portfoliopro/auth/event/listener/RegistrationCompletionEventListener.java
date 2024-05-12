package com.portfoliopro.auth.event.listener;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.portfoliopro.auth.dto.MailBody;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.VerificationToken;
import com.portfoliopro.auth.event.RegistrationCompletionEvent;
import com.portfoliopro.auth.service.EmailService;
import com.portfoliopro.auth.service.VerificationTokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompletionEventListener implements ApplicationListener<RegistrationCompletionEvent> {
    private final VerificationTokenService verificationTokenService;
    private final EmailService emailService;

    @Override
    public void onApplicationEvent(@NonNull RegistrationCompletionEvent event) {
        User user = event.getUser();
        VerificationToken token = verificationTokenService.createVerifyToken(user);
        if (token.equals(user.getVerificationToken())) {
            return;
        }

        String appUrl = event.getAppUrl() + "/auth/verifyEmail?token=" + token.getVerifyToken() + "&email="
                + user.getEmail();

        // todo: move this to a template
        String htmlTemplate = "<p> Hello, " + user.getFirstName() + " " + user.getLastName() + "</p>"
                + "<p> Thank you for registering with PortfolioPro. Please click the link below to verify your email address.</p>"
                + "<a href=\"" + appUrl + "\">Verify Email</a>";

        MailBody mailBody = new MailBody(user.getEmail(), "Verify Email", htmlTemplate);
        try {
            emailService.sendEmail(mailBody);
        } catch (Exception e) {
            log.error("Error sending email: " + e.getMessage());
        }
    }

}
