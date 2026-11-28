package com.authcore.auth.mfa;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.authcore.auth.audit.AuditEvent;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.ErrorCode;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.notification.SecurityAlert;
import com.authcore.auth.notification.SecurityNotifier;
import com.authcore.auth.ratelimit.TooManyRequestsException;
import com.authcore.auth.security.PasswordConfirmation;
import com.authcore.auth.security.Reauthentication;
import com.authcore.auth.session.ClientInfo;
import com.authcore.auth.token.InvalidCodeException;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserNotFoundException;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * Two-factor authentication with an authenticator app (F5). A user turns it on in two steps:
 * {@link #setUp} hands out a new secret for the app, and {@link #enable} takes the first code
 * the app shows, which proves the app has it. From then on every password login also needs
 * a code ({@link #checkLogin}), or one of ten recovery codes.
 *
 * <p>Codes are checked under the user's row lock, like everything else that changes the
 * user's rows: a code works once, and guesses at once can't get past the limit. Five wrong
 * codes in a row stop the checks for 15 minutes. That count is in the database, so it holds
 * while Redis is down.
 */
@Service
@RequiredArgsConstructor
public class TwoFactorService {
    static final int RECOVERY_CODES = 10;
    static final String WRONG_CODE = "The code is wrong.";

    private static final Pattern APP_CODE = Pattern.compile("\\d{" + Totp.DIGITS + "}");
    private static final Pattern RECOVERY_CODE = Pattern.compile("[a-z2-7]{10}");
    private static final String RECOVERY_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final TotpCredentialRepository credentials;
    private final RecoveryCodeRepository recoveryCodes;
    private final SecretCipher cipher;
    private final UserRepository userRepository;
    private final RetryingTransaction transaction;
    private final Reauthentication reauthentication;
    private final AuditLog audit;
    private final SecurityNotifier notifier;
    private final AuthConfigProperties properties;

    /** How a code was accepted. */
    public enum Method {
        APP, RECOVERY_CODE
    }

    public boolean isEnabled(Integer userId) {
        return credentials.isEnabled(userId);
    }

    /** Which of these users have it on, in one query (for the admins' user list). */
    public Set<Integer> enabledAmong(Collection<Integer> userIds) {
        return userIds.isEmpty() ? Set.of() : Set.copyOf(credentials.findEnabled(userIds));
    }

    public TwoFactorStatus status(Integer userId) {
        boolean enabled = credentials.isEnabled(userId);
        return new TwoFactorStatus(enabled, enabled ? recoveryCodes.countByUserIdAndUsedAtIsNull(userId) : 0);
    }

    /**
     * Starts the setup with a new secret, which replaces one from an unfinished setup.
     * Nothing changes at login until {@link #enable}.
     *
     * @throws TwoFactorStateException if it's on already
     */
    public TotpSetup setUp(Integer userId, String password, ClientInfo client) {
        User checked = reauthentication.check(new PasswordConfirmation(userId, password, client.ip()));
        byte[] secret = new byte[Totp.SECRET_BYTES];
        RANDOM.nextBytes(secret);
        transaction.run(() -> {
            lock(userId);
            Optional<TotpCredential> existing = credentials.findById(userId);
            if (existing.filter(TotpCredential::isEnabled).isPresent())
                throw new TwoFactorStateException(ErrorCode.TWO_FACTOR_ALREADY_ENABLED,
                        "Two-factor authentication is on already. Turn it off first to use another app.");
            existing.ifPresent(credentials::delete);
            credentials.flush();
            return credentials.save(new TotpCredential(userId, cipher.encrypt(userId, secret), Instant.now()));
        });
        String key = Totp.base32(secret);
        return new TotpSetup(key, otpauthUri(checked.getEmail(), key));
    }

    /**
     * Turns it on with the first code from the app.
     *
     * @return the recovery codes, shown this once
     * @throws TwoFactorStateException if there is no setup to finish
     * @throws InvalidCodeException    if the code is wrong
     */
    public List<String> enable(Integer userId, String code, ClientInfo client) {
        Result<List<String>> result = transaction.run(() -> {
            lock(userId);
            TotpCredential credential = credentials.findById(userId).filter(found -> !found.isEnabled())
                    .orElseThrow(() -> new TwoFactorStateException(ErrorCode.TWO_FACTOR_NOT_SET_UP,
                            "Start the setup first: POST /api/v1/users/me/2fa/setup."));
            CodeCheck check = check(credential, code, false);
            if (check.method() == null)
                return Result.<List<String>>failed(check);
            credential.enable(Instant.now());
            return Result.of(newRecoveryCodes(userId));
        });
        List<String> codes = result.orThrow();
        audit.record(AuditEvent.TWO_FACTOR_ENABLED, userId);
        notifier.send(userId, SecurityAlert.TWO_FACTOR_ENABLED, client);
        return codes;
    }

    /**
     * Turns it off. Needs the password and a code (or a recovery code): a stolen session alone
     * mustn't be enough.
     */
    public void disable(Integer userId, String password, String code, ClientInfo client) {
        reauthentication.check(new PasswordConfirmation(userId, password, client.ip()));
        transaction.run(() -> {
            CodeCheck check = check(enabledCredential(userId), code, true);
            if (check.method() == null)
                return Result.<Boolean>failed(check);
            remove(userId);
            return Result.of(true);
        }).orThrow();
        audit.record(AuditEvent.TWO_FACTOR_DISABLED, userId);
        notifier.send(userId, SecurityAlert.TWO_FACTOR_DISABLED, client);
    }

    /** New recovery codes, which replace the old ones. Needs the password and a code. */
    public List<String> newRecoveryCodes(Integer userId, String password, String code, ClientInfo client) {
        reauthentication.check(new PasswordConfirmation(userId, password, client.ip()));
        List<String> codes = transaction.run(() -> {
            CodeCheck check = check(enabledCredential(userId), code, true);
            if (check.method() == null)
                return Result.<List<String>>failed(check);
            return Result.of(newRecoveryCodes(userId));
        }).orThrow();
        audit.record(AuditEvent.RECOVERY_CODES_RENEWED, userId);
        return codes;
    }

    /**
     * The second step of a login.
     *
     * @param tokenVersion the user's version when the password was checked
     * @return how the code was accepted; empty if the password, the account or its
     *         two-factor setting changed since (the login has to start again)
     * @throws InvalidCodeException       if the code is wrong
     * @throws TooManyRequestsException   after too many wrong codes
     */
    public Optional<Method> checkLogin(Integer userId, int tokenVersion, String code) {
        Result<Optional<Method>> result = transaction.run(() -> {
            Optional<TotpCredential> credential = userRepository.findAndLockById(userId)
                    .filter(user -> user.getTokenVersion() == tokenVersion)
                    .flatMap(user -> credentials.findById(userId))
                    .filter(TotpCredential::isEnabled);
            if (credential.isEmpty())
                return Result.of(Optional.<Method>empty());
            CodeCheck check = check(credential.get(), code, true);
            return check.method() == null ? Result.<Optional<Method>>failed(check) : Result.of(Optional.of(check.method()));
        });
        return result.orThrow();
    }

    public int recoveryCodesLeft(Integer userId) {
        return recoveryCodes.countByUserIdAndUsedAtIsNull(userId);
    }

    /**
     * Turns it off without a code, for an admin helping a user who lost both their phone and
     * their recovery codes. The caller has locked the user's row.
     *
     * @return whether it was on
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public boolean remove(Integer userId) {
        boolean wasEnabled = credentials.isEnabled(userId);
        credentials.deleteById(userId);
        recoveryCodes.deleteByUserId(userId);
        return wasEnabled;
    }

    // ---- codes ---------------------------------------------------------------------

    /**
     * Checks a code from the app, or a recovery code, and counts a wrong one. Never throws:
     * the transaction has to commit, or a wrong code wouldn't count.
     */
    private CodeCheck check(TotpCredential credential, String input, boolean recoveryCodeAllowed) {
        Instant now = Instant.now();
        Duration locked = credential.lockedFor(now);
        if (!locked.isZero())
            return new CodeCheck(null, locked);

        String code = input.replaceAll("[\\s-]", "").toLowerCase(Locale.ROOT);
        Integer userId = credential.getUserId();
        if (APP_CODE.matcher(code).matches()) {
            byte[] secret = cipher.decrypt(userId, credential.getSecret());
            long current = Totp.step(now);
            // One step either side, for clocks that are a little off.
            for (long step = current - 1; step <= current + 1; step++) {
                if (step > credential.getLastUsedStep()
                        && MessageDigest.isEqual(Totp.code(secret, step).getBytes(US_ASCII), code.getBytes(US_ASCII))) {
                    credential.succeeded(step);
                    return new CodeCheck(Method.APP, Duration.ZERO);
                }
            }
        } else if (recoveryCodeAllowed && RECOVERY_CODE.matcher(code).matches()) {
            Optional<RecoveryCode> recovery = recoveryCodes.findByUserIdAndCodeHashAndUsedAtIsNull(userId,
                    cipher.hash(userId, code));
            if (recovery.isPresent()) {
                recovery.get().use(now);
                credential.succeeded(credential.getLastUsedStep());
                return new CodeCheck(Method.RECOVERY_CODE, Duration.ZERO);
            }
        }
        credential.failed(now);
        return new CodeCheck(null, Duration.ZERO);
    }

    private List<String> newRecoveryCodes(Integer userId) {
        recoveryCodes.deleteByUserId(userId);
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < RECOVERY_CODES; i++) {
            StringBuilder code = new StringBuilder();
            for (int c = 0; c < 10; c++)
                code.append(RECOVERY_ALPHABET.charAt(RANDOM.nextInt(RECOVERY_ALPHABET.length())));
            recoveryCodes.save(new RecoveryCode(userId, cipher.hash(userId, code.toString())));
            codes.add(code.substring(0, 5) + "-" + code.substring(5));
        }
        return codes;
    }

    private TotpCredential enabledCredential(Integer userId) {
        lock(userId);
        return credentials.findById(userId).filter(TotpCredential::isEnabled)
                .orElseThrow(() -> new TwoFactorStateException(ErrorCode.TWO_FACTOR_NOT_ENABLED,
                        "Two-factor authentication is off."));
    }

    private void lock(Integer userId) {
        // The access token was checked a moment ago, so the user exists, unless just deleted.
        userRepository.findAndLockById(userId).orElseThrow(() -> new UserNotFoundException(userId));
    }

    /** The link authenticator apps read from a QR code (Key Uri Format). */
    private String otpauthUri(String email, String key) {
        String issuer = properties.getTotp().getIssuer();
        return "otpauth://totp/" + encode(issuer + ":" + email) + "?secret=" + key + "&issuer=" + encode(issuer)
                + "&algorithm=SHA1&digits=" + Totp.DIGITS + "&period=" + Totp.STEP.toSeconds();
    }

    private static String encode(String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** @param method null if the code was wrong, or not checked because of {@code locked} */
    private record CodeCheck(@Nullable Method method, Duration locked) {
    }

    /** What a transaction found, thrown only after it committed. */
    private record Result<T>(@Nullable T value, @Nullable CodeCheck failure) {
        static <T> Result<T> of(T value) {
            return new Result<>(value, null);
        }

        static <T> Result<T> failed(CodeCheck failure) {
            return new Result<>(null, failure);
        }

        T orThrow() {
            if (failure == null)
                return value;
            if (!failure.locked().isZero())
                throw new TooManyRequestsException(failure.locked());
            throw new InvalidCodeException(WRONG_CODE);
        }
    }
}
