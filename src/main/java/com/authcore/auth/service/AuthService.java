package com.authcore.auth.service;

import java.time.Duration;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
import com.authcore.auth.exception.UserAlreadyExistsException;
import com.authcore.auth.entities.RefreshToken;
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
                                .role(Role.USER)
                                .enabled(false)
                                .build();

                userService.saveUser(user);

                return verifyEmail(user.getEmail(), null);
        }

        public AuthResponse loginUser(LoginRequest request, HttpServletResponse response) {
                String email = EmailAddresses.normalize(request.getEmail());
                User user = userService.getUserByEmail(email);
                if (user == null)
                        throw new UsernameNotFoundException(email + " user not found");

                manager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                email,
                                                request.getPassword()));

                String accessToken = jwtService.generateToken(user);
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
                RefreshToken refToken = refereshTokenService.verifyRefereshToken(refreshToken);
                User user = refToken.getUser();

                String accessToken = jwtService.generateToken(user);
                return AuthResponse.builder()
                                .accessToken(accessToken)
                                .build();
        }

        public MsgResponse verifyEmail(String email, String token) {
                email = EmailAddresses.normalize(email);
                User user = userService.getUserByEmail(email);

                if (user == null)
                        throw new UsernameNotFoundException(email + " user not found");

                if (user.isEnabled())
                        return MsgResponse.builder()
                                        .msg("Email already verified")
                                        .build();

                if (token == null) {
                        tokenService.createTokenAndSendMail(user,
                                        TokenType.VERFICATION_TOKEN);

                        return MsgResponse.builder()
                                        .msg("Verification email sent")
                                        .build();
                }

                tokenService.verifyToken(user, token, TokenType.VERFICATION_TOKEN);
                user.setEnabled(true);
                userService.saveUser(user);

                return MsgResponse.builder()
                                .msg("Email verified successfully")
                                .build();
        }

        public MsgResponse resetPassword(String email, @Nullable ResetPasswordRequest request) {
                email = EmailAddresses.normalize(email);
                User user = userService.getUserByEmail(email);
                if (user == null)
                        throw new UsernameNotFoundException(email + " user not found");

                if (!user.isEnabled())
                        return MsgResponse.builder()
                                        .msg("Email not verified")
                                        .build();

                if (request == null) {
                        tokenService.createTokenAndSendMail(user,
                                        TokenType.RESET_PASSWORD_TOKEN);

                        return MsgResponse.builder()
                                        .msg("Password reset email sent")
                                        .build();

                }

                tokenService.verifyToken(user, String.valueOf(request.getOtp()), TokenType.RESET_PASSWORD_TOKEN);
                user.setPassword(passwordEncoder.encode(request.getPassword()));
                userService.saveUser(user);
                return MsgResponse.builder()
                                .msg("Password reset successfully")
                                .build();
        }
}
