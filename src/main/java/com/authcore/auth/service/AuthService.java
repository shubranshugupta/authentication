package com.authcore.auth.service;

import java.time.Duration;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.authcore.auth.config.properties.AuthConfigProperties;
import com.authcore.auth.dto.response.AuthResponse;
import com.authcore.auth.dto.response.MsgResponse;
import com.authcore.auth.dto.request.LoginRequest;
import com.authcore.auth.dto.request.RegisterRequest;
import com.authcore.auth.dto.request.ResetPasswordRequest;
import com.authcore.auth.entities.Role;
import com.authcore.auth.entities.User;
import com.authcore.auth.exception.InvalidTokenException;
import com.authcore.auth.exception.TokenAlreadyExistsException;
import com.authcore.auth.exception.UserAlreadyExistsException;
import com.authcore.auth.service.token.TokenType;
import com.authcore.auth.validation.EmailAddresses;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
        private final UserService userService;
        private final PasswordEncoder passwordEncoder;
        private final JwtService jwtService;
        private final RefereshTokenService refereshTokenService;
        private final AuthenticationManager manager;
        private final TokenServiceFacade tokenService;
        private final AuthConfigProperties authConfigProperties;

        public static final String REFRESH_COOKIE = "refreshToken";

        // Browsers only send the cookie to paths under this one, so it reaches
        // /auth/refresh and nothing else. Must change if the auth endpoints move.
        private static final String REFRESH_COOKIE_PATH = "/auth";

        // H2: these requests get the same answer whether or not the account exists,
        // is verified, or already has an active code, so they can't be used to find
        // out which emails are registered.
        static final String VERIFICATION_REQUESTED = "If an account with this email exists and isn't verified yet, a verification email has been sent.";
        static final String RESET_REQUESTED = "If an account with this email exists, a password reset email has been sent.";
        static final String INVALID_VERIFICATION_LINK = "This verification link is invalid or has expired. If your email is already verified, you can log in.";
        static final String INVALID_OTP = "The code is invalid or has expired.";

        public MsgResponse registerUser(RegisterRequest request) {
                String email = EmailAddresses.normalize(request.getEmail());
                User user = userService.getUserByEmail(email);
                if (user != null)
                        throw new UserAlreadyExistsException(email + " already exists");

                user = User.builder()
                                .firstName(request.getFirstName())
                                .lastName(request.getLastName())
                                .email(email)
                                .password(passwordEncoder.encode(request.getPassword()))
                                .role(authConfigProperties.isAdminEmail(email) ? Role.ADMIN : Role.USER)
                                .enabled(false)
                                .build();

                User saved = saveNewUser(user);
                tokenService.createTokenAndSendMail(saved, TokenType.VERFICATION_TOKEN);

                return MsgResponse.builder()
                                .msg("Verification email sent")
                                .build();
        }

        public AuthResponse loginUser(LoginRequest request, HttpServletResponse response) {
                String email = EmailAddresses.normalize(request.getEmail());

                // H2: check the password first. An unknown email then fails exactly like
                // a wrong password (401), instead of revealing that it isn't registered.
                manager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                email,
                                                request.getPassword()));
                User user = userService.getUserByEmail(email);

                String accessToken = jwtService.generateToken(user.getEmail());
                String refreshToken = refereshTokenService.createRefereshToken(user)
                                .getRefreshToken();

                AuthConfigProperties.CookieConfigProperties cookieConfig = authConfigProperties.getCookie();
                ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, refreshToken)
                                .httpOnly(true)
                                .secure(cookieConfig.isSecure())
                                .sameSite(cookieConfig.getSameSite())
                                .path(REFRESH_COOKIE_PATH)
                                .maxAge(Duration.ofMillis(authConfigProperties.getToken().getRefreshExpiration()))
                                .build();

                response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
                return AuthResponse.builder()
                                .accessToken(accessToken)
                                .build();
        }

        public AuthResponse verifyRefreshToken(String refreshToken) {
                User user = refereshTokenService.verifyRefereshToken(refreshToken);

                String accessToken = jwtService.generateToken(user.getEmail());
                return AuthResponse.builder()
                                .accessToken(accessToken)
                                .build();
        }

        public MsgResponse verifyEmail(String email, String token) {
                email = EmailAddresses.normalize(email);
                User user = userService.getUserByEmail(email);

                if (token == null) {
                        if (user != null && !user.isEnabled())
                                sendTokenUnlessOneIsActive(user, TokenType.VERFICATION_TOKEN);

                        return MsgResponse.builder()
                                        .msg(VERIFICATION_REQUESTED)
                                        .build();
                }

                if (user == null || user.isEnabled())
                        throw new InvalidTokenException(INVALID_VERIFICATION_LINK);

                verifyToken(user, token, TokenType.VERFICATION_TOKEN, INVALID_VERIFICATION_LINK);
                user.setEnabled(true);
                userService.saveUser(user);

                return MsgResponse.builder()
                                .msg("Email verified successfully")
                                .build();
        }

        public MsgResponse resetPassword(String email, @Nullable ResetPasswordRequest request) {
                email = EmailAddresses.normalize(email);
                User user = userService.getUserByEmail(email);

                if (request == null) {
                        if (user != null && user.isEnabled())
                                sendTokenUnlessOneIsActive(user, TokenType.RESET_PASSWORD_TOKEN);

                        return MsgResponse.builder()
                                        .msg(RESET_REQUESTED)
                                        .build();
                }

                if (user == null || !user.isEnabled())
                        throw new InvalidTokenException(INVALID_OTP);

                verifyToken(user, String.valueOf(request.getOtp()), TokenType.RESET_PASSWORD_TOKEN, INVALID_OTP);
                user.setPassword(passwordEncoder.encode(request.getPassword()));
                userService.saveUser(user);
                // Whoever knew the old password may hold the refresh token. (The copy in the
                // Redis cache goes in Phase 5, C2.)
                refereshTokenService.deleteRefereshToken(user);
                return MsgResponse.builder()
                                .msg("Password reset successfully")
                                .build();
        }

        /**
         * Saves a new user. If the same email was registered at the same moment, the
         * unique constraint rejects this one, and it gets the usual "already exists".
         */
        private User saveNewUser(User user) {
                try {
                        return userService.saveUser(user);
                } catch (DataIntegrityViolationException e) {
                        if (userService.getUserByEmail(user.getEmail()) == null)
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
