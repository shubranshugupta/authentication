package com.authcore.auth.token;

import java.util.List;
import java.util.UUID;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.user.User;

@Service
public class VerificationTokenService extends TokenTemplate<VerificationToken> {
    private final VerificationTokenRepository verificationTokenRepository;

    public VerificationTokenService(VerificationTokenRepository verificationTokenRepository,
            ApplicationEventPublisher eventPublisher,
            AuthConfigProperties authConfigProperties) {
        super(verificationTokenRepository, eventPublisher, authConfigProperties);
        this.verificationTokenRepository = verificationTokenRepository;
    }

    @Override
    protected VerificationToken createNewToken() {
        return new VerificationToken();
    }

    @Override
    protected VerificationToken getTokenFromUser(User user) {
        return verificationTokenRepository.findByUser(user).orElse(null);
    }

    @Override
    protected String generateRandomTokenID() {
        return UUID.randomUUID().toString();
    }

    @Override
    protected void deleteToken(VerificationToken origToken) {
        verificationTokenRepository.deleteAllByIdInBatch(List.of(origToken.getId()));
    }

    @Override
    protected String getEmailSubject() {
        return "Verify Email";
    }

    @Override
    protected String getEmailTemplate() {
        return "verify_registration_email";
    }

    @Override
    protected String getEmailToken(User user, VerificationToken newToken) {
        return getAppUrl() + "/auth/verify-email?token=" + newToken.getToken() + "&email=" + user.getEmail();
    }
}
