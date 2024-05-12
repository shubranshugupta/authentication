package com.portfoliopro.auth.event.listener;

import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.VerificationToken;
import com.portfoliopro.auth.event.RegistrationCompletionEvent;
import com.portfoliopro.auth.service.VerificationTokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompletionEventListener implements ApplicationListener<RegistrationCompletionEvent> {
    private final VerificationTokenService verificationTokenService;

    @Override
    public void onApplicationEvent(@NonNull RegistrationCompletionEvent event) {
        User user = event.getUser();
        VerificationToken token = verificationTokenService.createVerifyToken(user);
        String appUrl = event.getAppUrl() + "/auth/verifyEmail?token=" + token.getVerifyToken() + "&email="
                + user.getEmail();

        // todo: send email

        log.info("verify: " + appUrl);
    }

}
