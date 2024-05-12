package com.portfoliopro.auth.event.listener;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

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

    @Override
    public void onApplicationEvent(@NonNull PasswordResetEvent event) {
        User user = event.getUser();
        Otp otp = passwordResetService.createOtp(user);

        // todo: move this to a template
        String htmlTemplate = "<p> Hello, " + user.getFirstName() + " " + user.getLastName() + "</p>"
                + "<p> You have requested to reset your password. Please use the OTP below to reset your password.</p>"
                + "<p> OTP: " + otp.getOtp() + "</p>";

        MailBody mailBody = new MailBody(user.getEmail(), "Password Reset", htmlTemplate);
        try {
            emailService.sendEmail(mailBody);
        } catch (Exception e) {
            log.error("Error sending email: " + e.getMessage());
        }
    }

}
