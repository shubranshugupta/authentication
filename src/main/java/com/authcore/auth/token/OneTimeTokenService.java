package com.authcore.auth.token;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

import org.jspecify.annotations.Nullable;
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
        return issue(userId, purpose, null);
    }

    /**
     * Like {@link #issue(Integer, TokenPurpose)}, for another address than the account's.
     *
     * @param email where the email goes, and what the account's email becomes once the code
     *              or link is used; null for the account's own address
     */
    @Transactional
    public boolean issue(Integer userId, TokenPurpose purpose, @Nullable String email) {
        User user = userRepository.findAndLockById(userId).orElse(null);
        if (user == null)
            return false;

        Instant now = Instant.now();
        OneTimeToken token = tokenRepository.findByUserIdAndPurpose(userId, purpose).orElse(null);
        if (token != null && now.isBefore(token.getIssuedAt().plus(RESEND_COOLDOWN)))
            return false;
        send(user, token, purpose, email, Map.of(), now);
        return true;
    }

    /**
     * Sends a new code or link at once, without the cooldown: for one the user didn't ask
     * for, such as the link that undoes an email change. It must reach the old address
     * however recently the last one was sent.
     *
     * @param user    locked
     * @param details more values for the email template
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void issueNow(User user, TokenPurpose purpose, String email, Map<String, Object> details) {
        send(user, tokenRepository.findByUserIdAndPurpose(user.getId(), purpose).orElse(null), purpose, email,
                details, Instant.now());
    }

    private void send(User user, @Nullable OneTimeToken token, TokenPurpose purpose, @Nullable String email,
            Map<String, Object> details, Instant now) {
        String plain = store(user, token, purpose, email, now);
        events.publishEvent(email(user, purpose, plain, email, details));
    }

    /**
     * A new token that isn't emailed but handed to the caller, e.g. for the redirect after
     * signing in with Google. It replaces the user's last one for this purpose.
     *
     * @param user locked
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public String issueUnsent(User user, TokenPurpose purpose) {
        return store(user, tokenRepository.findByUserIdAndPurpose(user.getId(), purpose).orElse(null), purpose,
                null, Instant.now());
    }

    /** @return the token itself, of which only the hash is saved */
    private String store(User user, @Nullable OneTimeToken token, TokenPurpose purpose, @Nullable String email,
            Instant now) {
        if (token == null)
            token = new OneTimeToken(user.getId(), purpose);
        String plain = purpose.isLink() ? randomLinkToken() : randomCode();
        token.issue(hasher.hash(purpose, purpose.isLink() ? null : user.getId(), plain), email, now);
        tokenRepository.save(token);
        return plain;
    }

    /** Whether the user has an unused, unexpired code or link for this purpose. */
    @Transactional(propagation = Propagation.MANDATORY)
    public boolean hasUnused(Integer userId, TokenPurpose purpose) {
        Instant now = Instant.now();
        return tokenRepository.findByUserIdAndPurpose(userId, purpose)
                .filter(token -> token.getConsumedAt() == null && now.isBefore(token.getExpiresAt()))
                .isPresent();
    }

    /**
     * Whether an unused undo link can still change some account's email back to this one.
     * No other account may take the address meanwhile, or the link would stop working.
     */
    public boolean isReservedForUndo(String email) {
        return tokenRepository.existsUnused(email, TokenPurpose.EMAIL_CHANGE_UNDO, Instant.now());
    }

    /** Makes the user's codes and links for these purposes unusable, e.g. once the email changed. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void revoke(Integer userId, TokenPurpose... purposes) {
        tokenRepository.deleteByUserIdAndPurposeIn(userId, List.of(purposes));
    }

    /**
     * Uses up a link.
     *
     * @return its user, locked; empty if the link isn't valid
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<User> consumeLink(String token, TokenPurpose purpose) {
        return consumeLinkForEmail(token, purpose).map(Consumed::user);
    }

    /** Like {@link #consumeLink}, with the address the link was issued for. */
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<Consumed> consumeLinkForEmail(String token, TokenPurpose purpose) {
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
        return consumeCodeForEmail(userId, code, purpose, required).map(Consumed::user);
    }

    /** Like {@link #consumeCode}, with the address the code was issued for. */
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<Consumed> consumeCodeForEmail(Integer userId, String code, TokenPurpose purpose,
            Predicate<User> required) {
        return consume(userId, purpose, hasher.hash(purpose, userId, code), required);
    }

    private Optional<Consumed> consume(Integer userId, TokenPurpose purpose, String hash, Predicate<User> required) {
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
            return Optional.of(new Consumed(user, token.getEmail()));
        }
        token.countWrongAttempt();
        return Optional.empty();
    }

    private EmailRequested email(User user, TokenPurpose purpose, String plain, @Nullable String email,
            Map<String, Object> details) {
        Map<String, Object> vars = new HashMap<>(details); // not Map.of: the last name may be null
        vars.put("firstName", StringUtils.capitalize(user.getFirstName()));
        vars.put("lastName", StringUtils.capitalize(user.getLastName()));
        vars.put("token", purpose.isLink() ? link(purpose, plain) : plain);
        vars.put("validFor", purpose.validForText());
        vars.put("frontendUrl", properties.getFrontendUrl());
        return new EmailRequested(email != null ? email : user.getEmail(), purpose.emailSubject,
                purpose.emailTemplate, vars);
    }

    /**
     * @param user  locked
     * @param email the address the code or link was issued for; null for the account's own
     */
    public record Consumed(User user, @Nullable String email) {
    }

    /** The token alone: it says whose it is, and the email doesn't belong in a URL (H4). */
    private String link(TokenPurpose purpose, String plain) {
        return properties.frontendPage(purpose.page) + "?token=" + plain;
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
