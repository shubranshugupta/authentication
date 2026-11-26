package com.authcore.auth.auth;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.EmailAddresses;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.ratelimit.LoginThrottle;
import com.authcore.auth.security.AccessToken;
import com.authcore.auth.security.JwtService;
import com.authcore.auth.security.LoginDetails;
import com.authcore.auth.session.ClientInfo;
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

/** Registration, login and password reset. Knows nothing about HTTP (A5). */
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

    public void register(RegisterRequest request) {
        String email = EmailAddresses.normalize(request.getEmail());
        if (userRepository.findByEmail(email).isPresent())
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

    public TokenPair login(String email, String password, ClientInfo client) {
        String normalized = EmailAddresses.normalize(email);
        loginThrottle.beforeCheck(normalized, client.ip());
        LoginDetails user = checkPassword(normalized, password, client);
        loginThrottle.succeeded(normalized, client.ip());

        return sessions.open(user.getId(), user.getTokenVersion(), client)
                .map(this::tokenPair)
                // The account was deleted, or its password changed, a moment ago.
                .orElseThrow(() -> new BadCredentialsException("Bad credentials"));
    }

    private LoginDetails checkPassword(String email, String password, ClientInfo client) {
        try {
            return (LoginDetails) manager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)).getPrincipal();
        } catch (BadCredentialsException e) {
            // H2: an unknown email fails exactly like a wrong password (401), instead of
            // revealing that it isn't registered.
            throw e;
        } catch (AuthenticationException e) {
            // E.g. the email isn't verified, or the database failed.
            loginThrottle.notAGuess(email, client.ip());
            throw e;
        }
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

    /** Sends a password reset code, if there is a verified account with this email. */
    public void requestPasswordReset(String email) {
        userRepository.findByEmail(EmailAddresses.normalize(email))
                .filter(User::isEnabled)
                .ifPresent(user -> tokens.issue(user.getId(), TokenPurpose.PASSWORD_RESET));
    }

    public void resetPassword(String email, String code, String newPassword, String ip) {
        String normalized = EmailAddresses.normalize(email);
        User account = userRepository.findByEmail(normalized)
                .filter(User::isEnabled)
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
        loginThrottle.passwordChanged(normalized, ip);
    }

    private TokenPair tokenPair(SessionTokens session) {
        String accessToken = jwtService.generateToken(
                new AccessToken(session.userId(), session.tokenVersion(), session.sessionId()));
        return new TokenPair(accessToken, session.refreshToken(), session.validFor());
    }
}
