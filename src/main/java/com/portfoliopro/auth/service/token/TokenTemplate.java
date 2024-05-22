package com.portfoliopro.auth.service.token;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.jpa.repository.JpaRepository;

import com.portfoliopro.auth.dto.EmailDTO;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.Token;
import com.portfoliopro.auth.exception.InvalidTokenException;
import com.portfoliopro.auth.exception.TokenAlreadyExistsException;
import com.portfoliopro.auth.exception.TokenExpireException;

public abstract class TokenTemplate<T extends Token> {
    private final JpaRepository<T, Integer> tokenRepository;
    private final ApplicationEventPublisher eventPublisher;
    @Value("${auth.token.token-expiration}")
    private long expireTime;
    @Value("${auth.base-url}")
    private String APP_URL;

    public TokenTemplate(JpaRepository<T, Integer> tokenRepository, ApplicationEventPublisher eventPublisher) {
        this.tokenRepository = tokenRepository;
        this.eventPublisher = eventPublisher;
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

        if (origToken == null || !origToken.getToken().equals(token)) {
            throw new InvalidTokenException(token + " token is invalid");
        }

        if (origToken.getExpiryDate().isBefore(Instant.now())) {
            tokenRepository.delete(origToken);
            throw new TokenExpireException(token + " Token is expired");
        }

        deleteToken(origToken);
        return true;
    }

    public void publishEmailEvent(User user, T newToken) {
        EmailDTO tokenEmailDTO = getEmailDto(user, newToken);
        ApplicationEvent event = getApplicationEvent(user, tokenEmailDTO);
        eventPublisher.publishEvent(event);
    }

    public String getAppUrl() {
        return APP_URL;
    }

    protected abstract void deleteToken(T origToken);

    protected abstract T createNewToken();

    protected abstract T getTokenFromUser(User user);

    protected abstract String generateRandomTokenID();

    protected abstract ApplicationEvent getApplicationEvent(User user, EmailDTO tokenEmailDTO);

    protected abstract EmailDTO getEmailDto(User user, T newToken);
}
