package com.portfoliopro.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.dto.response.AuthResponse;
import com.portfoliopro.auth.dto.response.MsgResponse;
import com.portfoliopro.auth.dto.request.LoginRequest;
import com.portfoliopro.auth.dto.request.RegisterRequest;
import com.portfoliopro.auth.dto.request.ResetPasswordRequest;
import com.portfoliopro.auth.entities.Role;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.exception.UserAlreadyExistsException;
import com.portfoliopro.auth.entities.RefreshToken;
import com.portfoliopro.auth.service.token.TokenType;

import jakarta.servlet.http.Cookie;
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

        @Value("${auth.base-url}")
        private String APP_URL;

        @Value("${auth.token.refresh-expiration}")
        private long REFRESH_EXPIRATION;

        public MsgResponse registerUser(RegisterRequest request) {
                User user = userService.getUserByEmail(request.getEmail());
                if (user != null)
                        throw new UserAlreadyExistsException(request.getEmail() + " already exists");

                user = User.builder()
                                .firstName(request.getFirstName())
                                .lastName(request.getLastName())
                                .email(request.getEmail())
                                .password(passwordEncoder.encode(request.getPassword()))
                                .role(Role.USER)
                                .isEnabled(false)
                                .build();

                userService.saveUser(user);

                return verifyEmail(user.getEmail(), null);
        }

        public AuthResponse loginUser(LoginRequest request, HttpServletResponse response) {
                User user = userService.getUserByEmail(request.getEmail());
                if (user == null)
                        throw new UsernameNotFoundException(request.getEmail() + " user not found");

                manager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                request.getEmail(),
                                                request.getPassword()));

                String accessToken = jwtService.generateToken(user);
                String refreshToken = refereshTokenService.createRefereshToken(user)
                                .getRefreshToken();

                Cookie cookie = new Cookie("refreshToken", refreshToken);
                cookie.setPath(APP_URL + "/auth");
                cookie.setHttpOnly(true);
                cookie.setMaxAge((int) REFRESH_EXPIRATION / 1000);

                if (APP_URL.startsWith("https://")) {
                        cookie.setSecure(true);
                }

                response.addCookie(cookie);
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
