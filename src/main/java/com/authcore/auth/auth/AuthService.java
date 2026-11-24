package com.authcore.auth.auth;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.DeadlockRetry;
import com.authcore.auth.common.EmailAddresses;
import com.authcore.auth.security.JwtService;
import com.authcore.auth.session.RefreshTokenService;
import com.authcore.auth.token.InvalidTokenException;
import com.authcore.auth.token.TokenAlreadyExistsException;
import com.authcore.auth.token.TokenServiceFacade;
import com.authcore.auth.token.TokenType;
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
    static final String INVALID_OTP = "The code is invalid or has expired.";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager manager;
    private final TokenServiceFacade tokenService;
    private final AuthConfigProperties authConfigProperties;

    public void register(RegisterRequest request) {
        String email = EmailAddresses.normalize(request.getEmail());
        if (userRepository.findByEmail(email).isPresent())
            throw new UserAlreadyExistsException(email + " already exists");

        User saved = saveNewUser(User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(email)
                .password(passwordEncoder.encode(request.getPassword()))
                .role(authConfigProperties.isAdminEmail(email) ? Role.ADMIN : Role.USER)
                .enabled(false)
                .build());

        tokenService.createTokenAndSendMail(saved, TokenType.VERIFICATION_TOKEN);
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
                .ifPresent(user -> sendTokenUnlessOneIsActive(user, TokenType.VERIFICATION_TOKEN));
    }

    public void verifyEmail(String email, String token) {
        User user = userRepository.findByEmail(EmailAddresses.normalize(email))
                .filter(found -> !found.isEnabled())
                .orElseThrow(() -> new InvalidTokenException(INVALID_VERIFICATION_LINK));

        verifyToken(user, token, TokenType.VERIFICATION_TOKEN, INVALID_VERIFICATION_LINK);

        user.setEnabled(true);
        userRepository.save(user);
    }

    /** Sends a password reset code, if there is a verified account with this email. */
    public void requestPasswordReset(String email) {
        userRepository.findByEmail(EmailAddresses.normalize(email))
                .filter(User::isEnabled)
                .ifPresent(user -> sendTokenUnlessOneIsActive(user, TokenType.RESET_PASSWORD_TOKEN));
    }

    public void resetPassword(String email, String otp, String newPassword) {
        User user = userRepository.findByEmail(EmailAddresses.normalize(email))
                .filter(User::isEnabled)
                .orElseThrow(() -> new InvalidTokenException(INVALID_OTP));

        verifyToken(user, otp, TokenType.RESET_PASSWORD_TOKEN, INVALID_OTP);

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        // Whoever knew the old password may hold the refresh token. (The copy in the
        // Redis cache goes in Phase 5, C2.)
        refreshTokenService.deleteRefreshToken(user);
    }

    /**
     * Saves a new user. If the same email was registered at the same moment, the
     * unique constraint rejects this one, and it gets the usual "already exists".
     */
    private User saveNewUser(User user) {
        try {
            return DeadlockRetry.run(() -> userRepository.save(user));
        } catch (DataIntegrityViolationException e) {
            if (userRepository.findByEmail(user.getEmail()).isEmpty())
                throw e;
            throw new UserAlreadyExistsException(user.getEmail() + " already exists");
        }
    }

    /**
     * Checks a token, and gives a wrong one exactly the answer an unknown account
     * gets. With its own message, one made-up token showed whether the account
     * exists (H2).
     */
    private void verifyToken(User user, String token, TokenType tokenType, String invalidMessage) {
        try {
            tokenService.verifyToken(user, token, tokenType);
        } catch (InvalidTokenException e) {
            throw new InvalidTokenException(invalidMessage, e);
        }
    }

    /**
     * Sends a new token, unless an unexpired one was already sent. That case used to
     * return 409, which revealed that the account exists (H2). The user still has to
     * wait for the old token to expire; H3 (Phase 4) replaces this with a short
     * resend cooldown.
     */
    private void sendTokenUnlessOneIsActive(User user, TokenType tokenType) {
        try {
            tokenService.createTokenAndSendMail(user, tokenType);
        } catch (TokenAlreadyExistsException e) {
            // already sent; same answer either way
        }
    }
}
