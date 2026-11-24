package com.authcore.auth.token;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.URLEncoder;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.notification.EmailRequested;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * The codes and links sent by email: creates them, and checks them (A1).
 *
 * <p>Every method first locks the user's row, so requests for the same user take turns.
 * Guesses sent all at once can't get past the attempt limit, and only one of two requests
 * with the right code can use it. This needs READ COMMITTED (application.yml): what is
 * read after the lock must be what the previous request wrote.
 */
@Service
@RequiredArgsConstructor
public class OneTimeTokenService {
    /** How long a user waits before they can be sent another code for the same purpose (H3). */
    static final Duration RESEND_COOLDOWN = Duration.ofSeconds(60);

    // 8 digits: with 5 guesses per code and a new code at most once a minute, guessing
    // around the clock has a chance of about 0.007 % per day. With 6 it would be 0.7 %.
    private static final int CODE_DIGITS = 8;
    private static final int CODES = 100_000_000;
    private static final int LINK_TOKEN_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OneTimeTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final TokenHasher hasher;
    private final ApplicationEventPublisher events;
    private final AuthConfigProperties properties;

    /**
     * Sends the user a new code or link, which replaces the old one. The email goes out
     * once the transaction commits.
     *
     * @return false if nothing was sent, because the last one was sent less than
     *         {@link #RESEND_COOLDOWN} ago (or the user was just deleted)
     */
    @Transactional
    public boolean issue(Integer userId, TokenPurpose purpose) {
        User user = userRepository.findAndLockById(userId).orElse(null);
        if (user == null)
            return false;

        Instant now = Instant.now();
        OneTimeToken token = tokenRepository.findByUserIdAndPurpose(userId, purpose).orElse(null);
        if (token != null && now.isBefore(token.getIssuedAt().plus(RESEND_COOLDOWN)))
            return false;

        if (token == null)
            token = new OneTimeToken(userId, purpose);
        String plain = purpose.isLink() ? randomLinkToken() : randomCode();
        token.issue(hasher.hash(purpose, purpose.isLink() ? null : userId, plain), now);
        tokenRepository.save(token);

        events.publishEvent(email(user, purpose, plain));
        return true;
    }

    /**
     * Uses up a link.
     *
     * @return its user, locked; empty if the link isn't valid
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<User> consumeLink(String token, TokenPurpose purpose) {
        String hash = hasher.hash(purpose, null, token);
        return tokenRepository.findUserId(hash, purpose)
                .flatMap(userId -> consume(userId, purpose, hash, user -> true));
    }

    /**
     * Uses up a code, or counts a wrong guess.
     *
     * <p>Returns empty instead of throwing, because the caller has to commit: an exception
     * would roll the counted guess back, and guessing would be unlimited.
     *
     * @param required what else has to be right (e.g. the password); if it isn't, that
     *                 counts as a wrong guess too
     * @return the user, locked; empty if the code isn't valid
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<User> consumeCode(Integer userId, String code, TokenPurpose purpose, Predicate<User> required) {
        return consume(userId, purpose, hasher.hash(purpose, userId, code), required);
    }

    private Optional<User> consume(Integer userId, TokenPurpose purpose, String hash, Predicate<User> required) {
        User user = userRepository.findAndLockById(userId).orElse(null);
        if (user == null)
            return Optional.empty();

        Instant now = Instant.now();
        OneTimeToken token = tokenRepository.findByUserIdAndPurpose(userId, purpose).orElse(null);
        if (token == null || !token.isUsable(now))
            return Optional.empty();

        // "&", not "&&": always check both, so the time taken doesn't say which was wrong.
        if (token.hasHash(hash) & required.test(user)) {
            token.consume(now);
            return Optional.of(user);
        }
        token.countWrongAttempt();
        return Optional.empty();
    }

    private EmailRequested email(User user, TokenPurpose purpose, String plain) {
        Map<String, Object> vars = new HashMap<>(); // not Map.of: the last name may be null
        vars.put("firstName", StringUtils.capitalize(user.getFirstName()));
        vars.put("lastName", StringUtils.capitalize(user.getLastName()));
        vars.put("token", purpose.isLink() ? link(user, purpose, plain) : plain);
        vars.put("validFor", purpose.validForText());
        vars.put("baseUrl", properties.getBaseUrl());
        return new EmailRequested(user.getEmail(), purpose.emailSubject, purpose.emailTemplate, vars);
    }

    private String link(User user, TokenPurpose purpose, String plain) {
        return properties.getBaseUrl() + purpose.page + "?token=" + plain + "&email="
                + URLEncoder.encode(user.getEmail(), UTF_8);
    }

    private static String randomCode() {
        return String.format("%0" + CODE_DIGITS + "d", RANDOM.nextInt(CODES));
    }

    private static String randomLinkToken() {
        byte[] bytes = new byte[LINK_TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
