package com.authcore.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/** How passwords are hashed and checked at login. */
@Configuration
@RequiredArgsConstructor
public class AuthenticationConfig {
    private final UserRepository userRepository;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(this::loginDetails);
        // Check "disabled" (email not verified) only after the password matched. By
        // default Spring checks it first, so any password revealed that an unverified
        // account exists (H2). Unknown emails already fail like wrong passwords.
        provider.setPreAuthenticationChecks(user -> {
        });
        provider.setPostAuthenticationChecks(new AccountStatusUserDetailsChecker());
        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }

    /**
     * What the password check needs, for that check only. Not a UserDetailsService bean:
     * after login, requests are authenticated by JwtAuthFilter (with a UserPrincipal).
     */
    private UserDetails loginDetails(String email) {
        return userRepository.findByEmail(email)
                .map(user -> User.withUsername(user.getEmail())
                        .password(user.getPassword())
                        .roles(user.getRole().name())
                        .disabled(!user.isEnabled())
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
