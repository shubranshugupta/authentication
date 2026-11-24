package com.authcore.auth.service.token.impl;

import java.security.SecureRandom;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import com.authcore.auth.config.properties.AuthConfigProperties;
import com.authcore.auth.entities.User;
import com.authcore.auth.entities.token.impl.DeleteAccountOtp;
import com.authcore.auth.repository.DeleteAccountRepository;
import com.authcore.auth.service.token.TokenTemplate;

@Service
public class DeleteAccountService extends TokenTemplate<DeleteAccountOtp> {
    private final DeleteAccountRepository otpRepository;
    private final static SecureRandom random = new SecureRandom();

    public DeleteAccountService(DeleteAccountRepository otpRepository, ApplicationEventPublisher eventPublisher,
            AuthConfigProperties authConfigProperties) {
        super(otpRepository, eventPublisher, authConfigProperties);
        this.otpRepository = otpRepository;
    }

    @Override
    protected DeleteAccountOtp createNewToken() {
        return new DeleteAccountOtp();
    }

    @Override
    protected DeleteAccountOtp getTokenFromUser(User user) {
        return otpRepository.findByUser(user).orElse(null);
    }

    @Override
    protected String generateRandomTokenID() {
        return String.valueOf(random.nextLong(100_000, 999_999));
    }

    @Override
    protected void deleteToken(DeleteAccountOtp origToken) {
    }

    @Override
    protected String getEmailSubject() {
        return "Delete Account";
    }

    @Override
    protected String getEmailTemplate() {
        return "delete_account_email";
    }
}
