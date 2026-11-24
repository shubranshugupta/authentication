package com.authcore.auth.service.token;

import java.time.Instant;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.jpa.repository.JpaRepository;

import com.authcore.auth.dto.EmailDTO;
import com.authcore.auth.entities.User;
import com.authcore.auth.entities.token.Token;
import com.authcore.auth.exception.InvalidTokenException;
import com.authcore.auth.exception.TokenAlreadyExistsException;
import com.authcore.auth.exception.TokenExpireException;

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

        // Tokens are deleted by id with a bulk query (here, in the subclasses and in
        // RefereshTokenService): unlike delete(entity), it is harmless when another
        // request deleted the row first. Phase 4 (A1) replaces these token tables.
        if (token != null)
            tokenRepository.deleteAllByIdInBatch(List.of(token.getId()));

        token = createNewToken();
        token.setToken(generateRandomTokenID());
        token.setUser(user);
        token.setExpiryDate(Instant.now().plusMillis(expireTime));
        try {
            tokenRepository.save(token);
        } catch (DataIntegrityViolationException e) {
            // Another request created this user's token at the same moment (one token
            // per user is allowed). Answer as if it had already been there: a 500 would
            // show that the account exists (H2).
            if (getTokenFromUser(user) == null)
                throw e;
            throw new TokenAlreadyExistsException("Token already exists");
        }

        return token;
    }

    public boolean verifyToken(User user, String token) {
        T origToken = getTokenFromUser(user);

        if (origToken == null || !origToken.getToken().equals(token)) {
            // Never echo the token: error responses and logs must not contain it (H2).
            throw new InvalidTokenException("The code or link is invalid or has expired.");
        }

        if (origToken.getExpiryDate().isBefore(Instant.now())) {
            tokenRepository.deleteAllByIdInBatch(List.of(origToken.getId()));
            throw new TokenExpireException("The code or link is invalid or has expired.");
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
