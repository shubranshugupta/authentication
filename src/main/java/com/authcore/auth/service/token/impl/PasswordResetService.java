package com.authcore.auth.service.token.impl;

import java.security.SecureRandom;
import java.util.List;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import com.authcore.auth.config.properties.AuthConfigProperties;
import com.authcore.auth.entities.User;
import com.authcore.auth.entities.token.impl.PasswordResetOtp;
import com.authcore.auth.repository.PasswordResetRepository;
import com.authcore.auth.service.token.TokenTemplate;

@Service
public class PasswordResetService extends TokenTemplate<PasswordResetOtp> {
    private final PasswordResetRepository otpRepository;
    private final static SecureRandom random = new SecureRandom();

    public PasswordResetService(PasswordResetRepository otpRepository, ApplicationEventPublisher eventPublisher,
            AuthConfigProperties authConfigProperties) {
        super(otpRepository, eventPublisher, authConfigProperties);
        this.otpRepository = otpRepository;
    }

    @Override
    protected PasswordResetOtp createNewToken() {
        return new PasswordResetOtp();
    }

    @Override
    protected PasswordResetOtp getTokenFromUser(User user) {
        return otpRepository.findByUser(user).orElse(null);
    }

    @Override
    protected String generateRandomTokenID() {
        return String.valueOf(random.nextLong(100_000, 999_999));
    }

    @Override
    protected void deleteToken(PasswordResetOtp origToken) {
        otpRepository.deleteAllByIdInBatch(List.of(origToken.getId()));
    }

    @Override
    protected String getEmailSubject() {
        return "Password Reset";
    }

    @Override
    protected String getEmailTemplate() {
        return "password_reset_email";
    }
}
