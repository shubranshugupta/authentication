package com.portfoliopro.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.dto.response.AuthResponse;
import com.portfoliopro.auth.dto.response.MsgResponse;
import com.portfoliopro.auth.dto.TokenEmailDTO;
import com.portfoliopro.auth.dto.request.LoginRequest;
import com.portfoliopro.auth.dto.request.RefreshTokenRequest;
import com.portfoliopro.auth.dto.request.RegisterRequest;
import com.portfoliopro.auth.dto.request.ResetPasswordRequest;
import com.portfoliopro.auth.entities.Role;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.entities.token.VerificationToken;
import com.portfoliopro.auth.event.PasswordResetEvent;
import com.portfoliopro.auth.event.RegistrationCompletionEvent;
import com.portfoliopro.auth.exception.UserAlreadyExistsException;
import com.portfoliopro.auth.entities.token.Otp;
import com.portfoliopro.auth.entities.RefreshToken;
import com.portfoliopro.auth.repository.UserRepository;
import com.portfoliopro.auth.service.token.TokenType;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final JwtService jwtService;
        private final RefereshTokenService refereshTokenService;
        private final AuthenticationManager manager;
        private final ApplicationEventPublisher eventPublisher;
        private final TokenServiceFacade tokenService;

        @Value("${auth.base-url}")
        private String APP_URL;

        public MsgResponse registerUser(RegisterRequest request, final HttpServletRequest httpRequest) {
                User user = userRepository.findByEmail(request.getEmail())
                                .orElse(null);
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

                userRepository.save(user);

                return verifyEmail(user.getEmail(), null, httpRequest);
        }

        public AuthResponse loginUser(LoginRequest request) {
                User user = userRepository.findByEmail(request.getEmail())
                                .orElseThrow(() -> new UsernameNotFoundException(
                                                request.getEmail() + " user not found"));

                manager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                request.getEmail(),
                                                request.getPassword()));

                String accessToken = jwtService.generateToken(user);
                String refreshToken = refereshTokenService.createRefereshToken(request.getEmail())
                                .getRefreshToken();
                return AuthResponse.builder()
                                .accessToken(accessToken)
                                .refreshToken(refreshToken)
                                .build();
        }

        public AuthResponse verifyRefreshToken(RefreshTokenRequest request) {
                RefreshToken refToken = refereshTokenService.verifyRefereshToken(request.getRefreshToken());
                User user = refToken.getUser();

                String accessToken = jwtService.generateToken(user);
                return AuthResponse.builder()
                                .accessToken(accessToken)
                                .refreshToken(request.getRefreshToken())
                                .build();
        }

        public MsgResponse verifyEmail(String email, String token, HttpServletRequest httpRequest) {
                User user = userRepository.findByEmail(email)
                                .orElseThrow(() -> new UsernameNotFoundException(email + " user not found"));

                if (user.isEnabled())
                        return MsgResponse.builder()
                                        .msg("Email already verified")
                                        .build();

                if (token == null) {
                        VerificationToken newToken = (VerificationToken) tokenService.createToken(user,
                                        TokenType.VERFICATION_TOKEN);
                        if (newToken.equals(user.getVerificationToken())) {
                                return MsgResponse.builder()
                                                .msg("Verification email already sent")
                                                .build();
                        }

                        String appUrl = APP_URL + "/auth/verifyEmail?token=" + newToken.getToken()
                                        + "&email=" + user.getEmail();

                        TokenEmailDTO tokenEmailDTO = TokenEmailDTO.builder()
                                        .email(user.getEmail())
                                        .firstName(user.getFirstName())
                                        .lastName(user.getLastName())
                                        .token(appUrl)
                                        .baseUrl(APP_URL)
                                        .build();

                        eventPublisher.publishEvent(new RegistrationCompletionEvent(user, tokenEmailDTO));

                        return MsgResponse.builder()
                                        .msg("Verification email sent")
                                        .build();
                }

                tokenService.verifyToken(user, token, TokenType.VERFICATION_TOKEN);
                user.setEnabled(true);
                userRepository.save(user);

                return MsgResponse.builder()
                                .msg("Email verified successfully")
                                .build();
        }

        public MsgResponse resetPassword(String email, @Nullable ResetPasswordRequest request,
                        HttpServletRequest httpRequest) {
                User user = userRepository.findByEmail(email)
                                .orElseThrow(() -> new UsernameNotFoundException(email + " user not found"));
                if (!user.isEnabled())
                        return MsgResponse.builder()
                                        .msg("Email not verified")
                                        .build();

                if (request == null) {
                        Otp otp = (Otp) tokenService.createToken(user, TokenType.RESET_PASSWORD_TOKEN);
                        if (otp.equals(user.getOtp())) {
                                return MsgResponse.builder()
                                                .msg("Otp already sent")
                                                .build();
                        }

                        TokenEmailDTO passwordResetDTO = TokenEmailDTO.builder()
                                        .email(user.getEmail())
                                        .firstName(user.getFirstName())
                                        .lastName(user.getLastName())
                                        .token(otp.getToken())
                                        .baseUrl(APP_URL)
                                        .build();

                        eventPublisher.publishEvent(new PasswordResetEvent(user, passwordResetDTO));

                        return MsgResponse.builder()
                                        .msg("Password reset email sent")
                                        .build();

                }

                tokenService.verifyToken(user, String.valueOf(request.getOtp()), TokenType.RESET_PASSWORD_TOKEN);
                user.setPassword(passwordEncoder.encode(request.getPassword()));
                userRepository.save(user);
                return MsgResponse.builder()
                                .msg("Password reset successfully")
                                .build();
        }
}
