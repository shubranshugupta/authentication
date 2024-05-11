package com.portfoliopro.auth.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.dto.response.AuthResponse;
import com.portfoliopro.auth.dto.request.LoginRequest;
import com.portfoliopro.auth.dto.request.RefreshTokenRequest;
import com.portfoliopro.auth.dto.request.RegisterRequest;
import com.portfoliopro.auth.entities.Role;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.exception.UserAlreadyExistsException;
import com.portfoliopro.auth.entities.RefreshToken;
import com.portfoliopro.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final JwtService jwtService;
        private final RefereshTokenService refereshTokenService;
        private final AuthenticationManager manager;

        public AuthResponse registerUser(RegisterRequest request) {
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
                                .build();

                userRepository.save(user);

                String accessToken = jwtService.generateToken(user);
                String refreshToken = refereshTokenService.createRefereshToken(request.getEmail())
                                .getRefreshToken();
                return AuthResponse.builder()
                                .accessToken(accessToken)
                                .refreshToken(refreshToken)
                                .build();
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
}
