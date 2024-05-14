package com.portfoliopro.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.VerificationToken;
import com.portfoliopro.auth.exception.InvalidTokenException;
import com.portfoliopro.auth.exception.TokenExpireException;
import com.portfoliopro.auth.repository.VerificationTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class VerificationTokenService {
    private final VerificationTokenRepository verificationTokenRepository;

    @Value("${auth.token.verify-expiration}")
    private long expireTime;

    public VerificationToken createVerifyToken(User user) {
        VerificationToken verificationToken = user.getVerificationToken();

        if (verificationToken != null && verificationToken.getExpiryDate().isAfter(Instant.now()))
            return verificationToken;

        if (verificationToken != null)
            verificationTokenRepository.delete(verificationToken);

        verificationToken = VerificationToken.builder()
                .user(user)
                .verifyToken(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(expireTime))
                .build();

        verificationTokenRepository.save(verificationToken);

        return verificationToken;
    }

    public boolean verifyToken(User user, String token) {
        VerificationToken verificationToken = user.getVerificationToken();

        if (verificationToken == null || !verificationToken.getVerifyToken().equals(token)) {
            throw new InvalidTokenException(token + " verification token is invalid",
                    new Throwable("Invalid verification token"));
        }

        if (verificationToken.getExpiryDate().isBefore(Instant.now())) {
            verificationTokenRepository.delete(verificationToken);
            throw new TokenExpireException(verificationToken + " Verification token is expired",
                    new Throwable("Verification token is expired"));
        }

        return true;
    }
}
