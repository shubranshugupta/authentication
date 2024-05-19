package com.portfoliopro.auth.service.token;

import java.util.Random;
import java.util.function.Supplier;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.repository.TokenRepository;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.Otp;
import com.portfoliopro.auth.entities.token.Token;
import com.portfoliopro.auth.entities.token.VerificationToken;
import com.portfoliopro.auth.exception.InvalidTokenException;
import com.portfoliopro.auth.exception.TokenExpireException;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TokenService<T extends Token> {
    private final TokenRepository<T> tokenRepository;

    @Value("${auth.token.verify-expiration}")
    private long expireTime;
    private static final Random random = new SecureRandom();

    public T createToken(User user, Supplier<T> tokenSupplier) {
        T token = tokenRepository.findByUser(user).orElse(null);

        if (token != null && token.getExpiryDate().isAfter(Instant.now()))
            return token;

        if (token != null)
            tokenRepository.delete(token);

        token = tokenSupplier.get();
        if (token instanceof VerificationToken) {
            token.setToken(UUID.randomUUID().toString());
        } else if (token instanceof Otp) {
            token.setToken(String.valueOf(generateRandomNumber()));
        } else {
            throw new IllegalArgumentException("Invalid token type");
        }
        token.setUser(user);
        token.setExpiryDate(Instant.now().plusMillis(expireTime));
        tokenRepository.save(token);

        return token;
    }

    public boolean verifyToken(User user, String token) {
        T origToken = tokenRepository.findByUser(user).orElseThrow(() -> new InvalidTokenException("Invalid token"));

        if (!origToken.getToken().equals(token)) {
            throw new InvalidTokenException(token + " token is invalid");
        }

        if (origToken.getExpiryDate().isBefore(Instant.now())) {
            tokenRepository.delete(origToken);
            throw new TokenExpireException(token + " Token is expired");
        }

        tokenRepository.delete(origToken);
        return true;
    }

    private long generateRandomNumber() {
        return random.nextLong(100_000, 999_999);
    }
}
