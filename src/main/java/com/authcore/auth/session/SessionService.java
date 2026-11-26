package com.authcore.auth.session;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.security.InvalidTokenException;
import com.authcore.auth.security.TokenExpireException;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Sessions and their refresh tokens (C2). Every refresh replaces the token. A token that
 * shows up again was copied, so then all of the user's sessions end: nobody can tell which
 * of the two is the owner.
 *
 * <p>Like in OneTimeTokenService, everything first locks the user's row, so that requests
 * for the same user take turns.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionService {
    /**
     * How long a replaced token may be sent again without being taken for a copy: two tabs
     * of a browser can refresh at the same moment, with the same cookie.
     */
    static final Duration REUSE_GRACE = Duration.ofSeconds(10);

    private static final String INVALID_TOKEN = "Invalid refresh token";
    private static final int TOKEN_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserSessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final RetryingTransaction transaction;
    private final AuthConfigProperties properties;

    /**
     * Opens a session for a user whose password was just checked.
     *
     * @param tokenVersion the user's version at that check
     * @return empty if the password or the account changed since
     */
    public Optional<SessionTokens> open(Integer userId, int tokenVersion, ClientInfo client) {
        return transaction.run(() -> userRepository.findAndLockById(userId)
                .filter(user -> user.getTokenVersion() == tokenVersion)
                .map(user -> {
                    Instant now = Instant.now();
                    sessionRepository.deleteExpired(userId, now);
                    return renew(user, new UserSession(userId, now), client, now);
                }));
    }

    /**
     * Exchanges a refresh token for a new one.
     *
     * @throws TokenExpireException  if its session has expired
     * @throws InvalidTokenException if it's unknown, its session has ended, or it was used before
     */
    public SessionTokens refresh(String token, ClientInfo client) {
        Refresh refresh = transaction.run(() -> tryToRefresh(hash(token), client));
        // Only now: an exception inside would roll back what ended the sessions.
        if (refresh.refused() != null)
            throw refresh.refused();
        return refresh.tokens();
    }

    private Refresh tryToRefresh(String hash, ClientInfo client) {
        User user = refreshTokenRepository.findUserId(hash).flatMap(userRepository::findAndLockById).orElse(null);
        if (user == null)
            return Refresh.refused(new InvalidTokenException(INVALID_TOKEN));
        // Read after the lock: the session may have ended, or the token been used, meanwhile.
        RefreshToken token = refreshTokenRepository.findByTokenHash(hash).orElse(null);
        if (token == null)
            return Refresh.refused(new InvalidTokenException(INVALID_TOKEN));
        UserSession session = sessionRepository.findById(token.getSessionId()).orElseThrow();

        Instant now = Instant.now();
        if (session.isExpired(now)) {
            sessionRepository.end(session.getId());
            return Refresh.refused(new TokenExpireException("Refresh token has expired"));
        }
        if (token.getUsedAt() == null) {
            token.use(now);
            return Refresh.of(renew(user, session, client, now));
        }
        // The other request got the new refresh token, and the cookie is shared. No second
        // one is handed out: a copied token could start a chain of its own unnoticed.
        if (now.isBefore(token.getUsedAt().plus(REUSE_GRACE)))
            return Refresh.of(tokens(user, session, null, now));

        log.warn("A used refresh token of user {} showed up again: ending all of their sessions", user.getId());
        endAll(user);
        return Refresh.refused(new InvalidTokenException(INVALID_TOKEN));
    }

    /** Ends the session of this refresh token, if there still is one. */
    public void close(String token) {
        String hash = hash(token);
        transaction.run(() -> refreshTokenRepository.findUserId(hash)
                .flatMap(userRepository::findAndLockById)
                .flatMap(user -> refreshTokenRepository.findByTokenHash(hash))
                .map(found -> {
                    sessionRepository.end(found.getSessionId());
                    return found;
                }));
    }

    /** The sessions of a user, the last used one first. */
    public List<SessionResponse> list(Integer userId, Long currentSessionId) {
        return sessionRepository.findByUserIdAndExpiresAtAfterOrderByLastUsedAtDescIdDesc(userId, Instant.now()).stream()
                .map(session -> SessionResponse.from(session, currentSessionId))
                .toList();
    }

    /** Ends one of the user's sessions. */
    public void end(Integer userId, Long sessionId) {
        transaction.run(() -> userRepository.findAndLockById(userId)
                .flatMap(user -> sessionRepository.findById(sessionId))
                .filter(session -> session.getUserId().equals(userId))
                .map(session -> {
                    sessionRepository.end(sessionId);
                    return session;
                }))
                // Also if it's somebody else's: whether that exists is none of their business.
                .orElseThrow(() -> new SessionNotFoundException(sessionId));
    }

    public void endAll(Integer userId) {
        transaction.run(() -> userRepository.findAndLockById(userId).map(user -> {
            endAll(user);
            return user;
        }));
    }

    /** Ends all sessions of this user, which the caller has locked. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void endAll(User user) {
        sessionRepository.endAll(user.getId());
        // Also stops a login whose password was checked before this, but which has no
        // session yet.
        user.invalidateAccessTokens();
        userRepository.save(user);
    }

    private SessionTokens renew(User user, UserSession session, ClientInfo client, Instant now) {
        session.use(client, now, expiry(session, now));
        sessionRepository.save(session);
        String token = randomToken();
        refreshTokenRepository.save(new RefreshToken(session.getId(), hash(token), now));
        return tokens(user, session, token, now);
    }

    /** Each use extends the session, but not forever. */
    private Instant expiry(UserSession session, Instant now) {
        Instant unused = now.plusMillis(properties.getToken().getRefreshExpiration());
        Instant atMost = session.getCreatedAt().plusMillis(properties.getToken().getSessionExpiration());
        return unused.isBefore(atMost) ? unused : atMost;
    }

    private static SessionTokens tokens(User user, UserSession session, @Nullable String token, Instant now) {
        return new SessionTokens(user.getId(), user.getTokenVersion(), session.getId(), token,
                Duration.between(now, session.getExpiresAt()));
    }

    private static String randomToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Without a key, unlike TokenHasher: a random token this long can't be guessed from its hash. */
    private static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // every Java has SHA-256
        }
    }

    /** Either the tokens, or why there are none. */
    private record Refresh(@Nullable SessionTokens tokens, @Nullable RuntimeException refused) {
        static Refresh of(SessionTokens tokens) {
            return new Refresh(tokens, null);
        }

        static Refresh refused(RuntimeException reason) {
            return new Refresh(null, reason);
        }
    }
}
