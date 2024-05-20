package com.portfoliopro.auth.service.token;

// import java.util.Random;
// import java.util.function.Supplier;
// import java.security.SecureRandom;
import java.time.Instant;
// import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.jpa.repository.JpaRepository;
// import org.springframework.stereotype.Service;

// import com.portfoliopro.auth.repository.TokenRepository;
import com.portfoliopro.auth.entities.User;
// import com.portfoliopro.auth.entities.token.Otp;
import com.portfoliopro.auth.entities.token.Token;
// import com.portfoliopro.auth.entities.token.VerificationToken;
import com.portfoliopro.auth.exception.InvalidTokenException;
import com.portfoliopro.auth.exception.TokenAlreadyExistsException;
import com.portfoliopro.auth.exception.TokenExpireException;

// import lombok.RequiredArgsConstructor;

public abstract class TokenTemplate<T extends Token> {
    private final JpaRepository<T, Integer> tokenRepository;
    @Value("${auth.token.token-expiration}")
    private long expireTime;

    public TokenTemplate(JpaRepository<T, Integer> tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    public T createToken(User user) {
        T token = getTokenFromUser(user);

        if (token != null && token.getExpiryDate().isAfter(Instant.now()))
            throw new TokenAlreadyExistsException("Token already exists");

        if (token != null)
            tokenRepository.delete(token);

        token = createNewToken();
        token.setToken(generateRandomTokenID());
        token.setUser(user);
        token.setExpiryDate(Instant.now().plusMillis(expireTime));
        tokenRepository.save(token);

        return token;
    }

    public boolean verifyToken(User user, String token) {
        T origToken = getTokenFromUser(user);

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

    protected abstract T createNewToken();

    protected abstract T getTokenFromUser(User user);

    protected abstract String generateRandomTokenID();
}
