package com.portfoliopro.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.VerificationToken;
import com.portfoliopro.auth.exception.ExpireVerificationTokenException;
import com.portfoliopro.auth.exception.InvalidVerificationTokenException;
import com.portfoliopro.auth.repository.VerificationTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class VerificationTokenService {
    private final VerificationTokenRepository verificationTokenRepository;

    @Value("${jwt.token.verify-expiration}")
    private long expireTime;

    public VerificationToken createVerifyToken(User user) {
        VerificationToken verificationToken = VerificationToken.builder()
                .user(user)
                .verifyToken(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(expireTime))
                .build();

        verificationTokenRepository.save(verificationToken);

        return verificationToken;
    }

    public VerificationToken verifyToken(String token) {
        VerificationToken verifyToken = verificationTokenRepository.findByVerifyToken(token)
                .orElseThrow(() -> new InvalidVerificationTokenException("Invalid token: " + token));

        if (verifyToken.getExpiryDate().isBefore(Instant.now())) {
            verificationTokenRepository.delete(verifyToken);
            throw new ExpireVerificationTokenException("Token: " + token + " is expired");
        }

        return verifyToken;
    }

    public void deleteVerifyToken(VerificationToken token) {
        verificationTokenRepository.delete(token);
    }
}
