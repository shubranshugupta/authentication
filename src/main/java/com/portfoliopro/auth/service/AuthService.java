package com.portfoliopro.auth.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.portfoliopro.auth.dto.AuthResponse;
import com.portfoliopro.auth.dto.LoginRequest;
import com.portfoliopro.auth.dto.RegisterRequest;
import com.portfoliopro.auth.entities.Role;
import com.portfoliopro.auth.entities.User;
import com.portfoliopro.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final JwtService jwtService;
        private final AuthenticationManager manager;

        public AuthResponse registerUser(RegisterRequest request) {
                User user = User.builder()
                                .firstName(request.getFirstName())
                                .lastName(request.getLastName())
                                .email(request.getEmail())
                                .password(passwordEncoder.encode(request.getPassword()))
                                .role(Role.USER)
                                .build();

                userRepository.save(user);

                String token = jwtService.generateToken(user);
                return AuthResponse.builder()
                                .token(token)
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

                String token = jwtService.generateToken(user);
                return AuthResponse.builder()
                                .token(token)
                                .build();
        }
}
