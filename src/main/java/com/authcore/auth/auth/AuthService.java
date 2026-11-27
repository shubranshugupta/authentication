package com.authcore.auth.auth;

import java.util.Optional;

import org.jspecify.annotations.Nullable;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authcore.auth.audit.AuditEvent;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.EmailAddresses;
import com.authcore.auth.common.ErrorCode;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.mfa.LoginChallenges;
import com.authcore.auth.mfa.TwoFactorService;
import com.authcore.auth.mfa.TwoFactorStateException;
import com.authcore.auth.notification.SecurityAlert;
import com.authcore.auth.notification.SecurityNotifier;
import com.authcore.auth.ratelimit.LoginThrottle;
import com.authcore.auth.ratelimit.TooManyRequestsException;
import com.authcore.auth.security.AccessToken;
import com.authcore.auth.security.InvalidTokenException;
import com.authcore.auth.security.JwtService;
import com.authcore.auth.security.LoginDetails;
import com.authcore.auth.security.PasswordConfirmation;
import com.authcore.auth.security.Reauthentication;
import com.authcore.auth.session.ClientInfo;
import com.authcore.auth.session.DeviceService;
import com.authcore.auth.session.DeviceService.DeviceCheck;
import com.authcore.auth.session.SessionService;
import com.authcore.auth.session.SessionTokens;
import com.authcore.auth.token.InvalidCodeException;
import com.authcore.auth.token.OneTimeTokenService;
import com.authcore.auth.token.TokenPurpose;
import com.authcore.auth.user.Role;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserAlreadyExistsException;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/** Registration, login, password reset and password change. Knows nothing about HTTP (A5). */
@Service
@RequiredArgsConstructor
public class AuthService {
    // H2: the same text whether the account doesn't exist, is in the wrong state, or the
    // token is wrong, so the answer can't be used to find out which emails are registered.
    static final String INVALID_VERIFICATION_LINK = "This verification link is invalid or has expired. If your email is already verified, you can log in.";
    static final String INVALID_CODE = "The code is invalid or has expired.";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final SessionService sessions;
    private final AuthenticationManager manager;
    private final LoginThrottle loginThrottle;
    private final OneTimeTokenService tokens;
    private final RetryingTransaction transaction;
    private final AuthConfigProperties authConfigProperties;
    private final AuditLog audit;
    private final Reauthentication reauthentication;
    private final DeviceService devices;
    private final SecurityNotifier notifier;
    private final TwoFactorService twoFactor;
    private final LoginChallenges challenges;

    public void register(RegisterRequest request) {
        String email = EmailAddresses.normalize(request.getEmail());
        // Or an account whose email was changed can still get it back (EmailChangeService).
        if (userRepository.findByEmail(email).isPresent() || tokens.isReservedForUndo(email))
            throw new UserAlreadyExistsException(email + " already exists");

        String passwordHash = passwordEncoder.encode(request.getPassword());
        try {
            // The account and its link together: an account without a link, if the second
            // step failed, would only keep the email taken (H5).
            transaction.run(() -> {
                User saved = userRepository.saveAndFlush(User.builder()
                        .firstName(request.getFirstName())
                        .lastName(request.getLastName())
                        .email(email)
                        .password(passwordHash)
                        .role(authConfigProperties.isAdminEmail(email) ? Role.ADMIN : Role.USER)
                        .enabled(false)
                        .build());
                return tokens.issue(saved.getId(), TokenPurpose.EMAIL_VERIFICATION);
            });
        } catch (DataIntegrityViolationException e) {
            // The same email was registered at the same moment, and the unique constraint
            // rejected this one.
            if (userRepository.findByEmail(email).isEmpty())
                throw e;
            throw new UserAlreadyExistsException(email + " already exists");
        }
    }

    /**
     * @param deviceId the client's device id (a cookie), null if it has none
     * @return the tokens, and the device id the client keeps from now on
     */
    public LoginResult login(String email, String password, ClientInfo client, @Nullable String deviceId) {
        String normalized = EmailAddresses.normalize(email);
        try {
            loginThrottle.beforeCheck(normalized, client.ip());
        } catch (TooManyRequestsException e) {
            loginFailed(normalized, "RATE_LIMITED");
            throw e;
        }
        LoginDetails user = checkPassword(normalized, password, client);
        loginThrottle.succeeded(normalized, client.ip());

        if (twoFactor.isEnabled(user.getId())) {
            audit.record(AuditEvent.SECOND_FACTOR_REQUIRED, user.getId());
            return LoginResult.secondFactorRequired(challenges.issue(user.getId(), user.getTokenVersion()));
        }
        return openSession(user.getId(), user.getTokenVersion(), client, deviceId, null);
    }

    /**
     * The second step of a login with two-factor authentication: the code from the app, or a
     * recovery code.
     *
     * @param challenge what the first step returned
     * @throws TwoFactorStateException  if the challenge expired, or the account changed since
     *                                  ({@code TWO_FACTOR_LOGIN_EXPIRED}: log in again)
     * @throws BadCredentialsException  if the code is wrong
     * @throws TooManyRequestsException after too many wrong codes
     */
    public LoginResult completeLogin(String challenge, String code, ClientInfo client, @Nullable String deviceId) {
        LoginChallenges.Challenge login = challenges.parse(challenge).orElseThrow(SecondFactor::expired);
        Optional<TwoFactorService.Method> method;
        try {
            method = twoFactor.checkLogin(login.userId(), login.tokenVersion(), code);
        } catch (InvalidCodeException e) {
            audit.record(AuditEvent.LOGIN_FAILED, login.userId(), "reason", "WRONG_CODE");
            throw new BadCredentialsException("Bad credentials", e);
        } catch (TooManyRequestsException e) {
            audit.record(AuditEvent.LOGIN_FAILED, login.userId(), "reason", "CODE_RATE_LIMITED");
            throw e;
        }
        if (method.isEmpty()) {
            audit.record(AuditEvent.LOGIN_FAILED, login.userId(), "reason", "EXPIRED");
            throw SecondFactor.expired();
        }
        LoginResult result = openSession(login.userId(), login.tokenVersion(), client, deviceId, method.get());
        if (method.get() == TwoFactorService.Method.RECOVERY_CODE)
            notifier.send(login.userId(), SecurityAlert.RECOVERY_CODE_USED, client);
        return result;
    }

    /**
     * @param secondFactor how the code was given; null for a user without two-factor authentication
     */
    private LoginResult openSession(Integer userId, int tokenVersion, ClientInfo client, @Nullable String deviceId,
            TwoFactorService.@Nullable Method secondFactor) {
        SessionTokens session = sessions.open(userId, tokenVersion, client)
                // The account was deleted, or its password changed, a moment ago.
                .orElseThrow(() -> {
                    audit.record(AuditEvent.LOGIN_FAILED, userId, "reason", "ACCOUNT_CHANGED");
                    return new BadCredentialsException("Bad credentials");
                });
        DeviceCheck device = devices.remember(session.userId(), deviceId);
        if (secondFactor == null)
            audit.record(AuditEvent.LOGIN_SUCCEEDED, session.userId(), "sessionId", session.sessionId(),
                    "newDevice", device.isNew());
        else
            audit.record(AuditEvent.LOGIN_SUCCEEDED, session.userId(), "sessionId", session.sessionId(),
                    "newDevice", device.isNew(), "secondFactor", secondFactor);
        if (device.isNew())
            notifier.send(session.userId(), SecurityAlert.NEW_DEVICE_LOGIN, client);
        return new LoginResult(tokenPair(session), device.deviceId(), null);
    }

    private static final class SecondFactor {
        static TwoFactorStateException expired() {
            return new TwoFactorStateException(ErrorCode.TWO_FACTOR_LOGIN_EXPIRED,
                    "The login has expired, or the account changed since. Log in again.");
        }
    }

    private LoginDetails checkPassword(String email, String password, ClientInfo client) {
        try {
            return (LoginDetails) manager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)).getPrincipal();
        } catch (BadCredentialsException e) {
            // H2: an unknown email fails exactly like a wrong password (401), instead of
            // revealing that it isn't registered.
            loginFailed(email, null);
            throw e;
        } catch (DisabledException e) {
            loginThrottle.notAGuess(email, client.ip());
            loginFailed(email, "EMAIL_NOT_VERIFIED");
            throw e;
        } catch (LockedException e) {
            loginThrottle.notAGuess(email, client.ip());
            loginFailed(email, "ACCOUNT_LOCKED");
            throw e;
        } catch (AuthenticationException e) {
            // E.g. the email isn't verified, or the database failed.
            loginThrottle.notAGuess(email, client.ip());
            throw e;
        }
    }

    /**
     * The audit log gets the account's id, never the email (F2). Both an unknown and a known
     * email cost this one query, so the time taken doesn't tell them apart (H2).
     *
     * @param reason null for a wrong password or an unknown email
     */
    private void loginFailed(String email, @Nullable String reason) {
        Integer userId = userRepository.findByEmail(email).map(User::getId).orElse(null);
        audit.record(AuditEvent.LOGIN_FAILED, userId, "reason",
                reason != null ? reason : userId != null ? "WRONG_PASSWORD" : "UNKNOWN_ACCOUNT");
    }

    public TokenPair refresh(String refreshToken, ClientInfo client) {
        return tokenPair(sessions.refresh(refreshToken, client));
    }

    public void logout(String refreshToken) {
        sessions.close(refreshToken);
    }

    /** Sends the verification email again, if there is an account that needs it. */
    public void resendVerification(String email) {
        userRepository.findByEmail(EmailAddresses.normalize(email))
                .filter(user -> !user.isEnabled())
                .ifPresent(user -> tokens.issue(user.getId(), TokenPurpose.EMAIL_VERIFICATION));
    }

    public void verifyEmail(String token) {
        boolean verified = transaction.run(() -> tokens.consumeLink(token, TokenPurpose.EMAIL_VERIFICATION)
                .map(user -> {
                    user.setEnabled(true);
                    userRepository.save(user);
                    return true;
                }).orElse(false));
        if (!verified)
            throw new InvalidCodeException(INVALID_VERIFICATION_LINK);
    }

    /** Sends a password reset code, if there is an account with this email that can log in. */
    public void requestPasswordReset(String email) {
        userRepository.findByEmail(EmailAddresses.normalize(email))
                .filter(AuthService::canResetPassword)
                .ifPresent(user -> tokens.issue(user.getId(), TokenPurpose.PASSWORD_RESET));
    }

    public void resetPassword(String email, String code, String newPassword, ClientInfo client) {
        String normalized = EmailAddresses.normalize(email);
        User account = userRepository.findByEmail(normalized)
                .filter(AuthService::canResetPassword)
                .orElseThrow(() -> new InvalidCodeException(INVALID_CODE));

        boolean reset = transaction.run(() -> tokens
                .consumeCode(account.getId(), code, TokenPurpose.PASSWORD_RESET, user -> true)
                .map(user -> {
                    user.setPassword(passwordEncoder.encode(newPassword));
                    userRepository.save(user);
                    // Whoever knew the old password may be logged in.
                    sessions.endAll(user);
                    return true;
                }).orElse(false));
        if (!reset)
            throw new InvalidCodeException(INVALID_CODE);
        loginThrottle.passwordChanged(normalized, client.ip());
        audit.record(AuditEvent.PASSWORD_RESET, account.getId());
        notifier.send(account.getId(), SecurityAlert.PASSWORD_RESET, client);
    }

    /**
     * Changes the password of a logged-in user, who types the current one again: a stolen
     * access token isn't enough. Logs out every other device, since whoever knew the old
     * password may be logged in there, but not this one.
     *
     * @return a new access token for this session: the old one stops working, like every
     *         other one; the refresh token stays the same
     * @throws com.authcore.auth.security.WrongPasswordException if the current password is wrong
     * @throws InvalidTokenException if this session ended, or the password changed, meanwhile
     */
    public String changePassword(Integer userId, Long sessionId, String currentPassword, String newPassword,
            ClientInfo client) {
        User checked = reauthentication.check(new PasswordConfirmation(userId, currentPassword, client.ip()));
        String passwordHash = passwordEncoder.encode(newPassword);

        SessionTokens session = transaction.run(() -> {
            User user = userRepository.findAndLockById(userId)
                    // A reset or another change raised the version, and ended this session.
                    .filter(found -> found.getTokenVersion() == checked.getTokenVersion())
                    .orElseThrow(() -> new InvalidTokenException(JwtService.INVALID_TOKEN));
            user.setPassword(passwordHash);
            // Throwing rolls the new password back.
            return sessions.endAllExcept(user, sessionId)
                    .orElseThrow(() -> new InvalidTokenException(JwtService.INVALID_TOKEN));
        });
        loginThrottle.passwordChanged(checked.getEmail(), client.ip());
        audit.record(AuditEvent.PASSWORD_CHANGED, userId, "sessionId", sessionId);
        notifier.send(userId, SecurityAlert.PASSWORD_CHANGED, client);
        return tokenPair(session).accessToken();
    }

    private static boolean canResetPassword(User user) {
        return user.isEnabled() && !user.isLocked();
    }

    private TokenPair tokenPair(SessionTokens session) {
        String accessToken = jwtService.generateToken(
                new AccessToken(session.userId(), session.tokenVersion(), session.sessionId()));
        return new TokenPair(accessToken, session.refreshToken(), session.validFor());
    }
}
