package com.portfoliopro.auth.service.token;

import java.util.UUID;

import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.VerificationToken;
import com.portfoliopro.auth.repository.VerificationTokenRepository;

@Service
public class VerificationTokenService extends TokenTemplate<VerificationToken> {
    private final VerificationTokenRepository verificationTokenRepository;

    public VerificationTokenService(VerificationTokenRepository verificationTokenRepository) {
        super(verificationTokenRepository);
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
        verificationTokenRepository.delete(origToken);
    }

}
