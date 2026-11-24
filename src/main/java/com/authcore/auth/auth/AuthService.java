package com.authcore.auth.auth;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.EmailAddresses;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.security.JwtService;
import com.authcore.auth.session.RefreshTokenService;
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
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager manager;
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

    public TokenPair login(String email, String password) {
        String normalized = EmailAddresses.normalize(email);

        // H2: check the password first. An unknown email then fails exactly like
        // a wrong password (401), instead of revealing that it isn't registered.
        manager.authenticate(new UsernamePasswordAuthenticationToken(normalized, password));

        // Only missing if the account was deleted a moment ago.
        User user = userRepository.findByEmail(normalized)
                .orElseThrow(() -> new BadCredentialsException("Bad credentials"));

        return new TokenPair(
                jwtService.generateToken(user.getEmail()),
                refreshTokenService.createRefreshToken(user).getRefreshToken());
    }

    /** Returns a new access token. */
    public String refresh(String refreshToken) {
        return jwtService.generateToken(refreshTokenService.verifyRefreshToken(refreshToken).getEmail());
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

    public void resetPassword(String email, String code, String newPassword) {
        User account = userRepository.findByEmail(EmailAddresses.normalize(email))
                .filter(User::isEnabled)
                .orElseThrow(() -> new InvalidCodeException(INVALID_CODE));

        boolean reset = transaction.run(() -> tokens
                .consumeCode(account.getId(), code, TokenPurpose.PASSWORD_RESET, user -> true)
                .map(user -> {
                    user.setPassword(passwordEncoder.encode(newPassword));
                    userRepository.save(user);
                    // Whoever knew the old password may hold the refresh token. (The copy in
                    // the Redis cache goes in Phase 5, C2.)
                    refreshTokenService.deleteRefreshToken(user);
                    return true;
                }).orElse(false));
        if (!reset)
            throw new InvalidCodeException(INVALID_CODE);
    }
}
