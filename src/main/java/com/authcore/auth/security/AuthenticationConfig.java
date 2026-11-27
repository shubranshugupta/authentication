package com.authcore.auth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/** How passwords are hashed and checked at login. */
@Configuration
@RequiredArgsConstructor
public class AuthenticationConfig {
    private final UserRepository userRepository;
    private final PasswordUpgrade passwordUpgrade;

    /** Argon2id for new hashes; bcrypt ones from before still match (PasswordHashing). */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordHashing.encoder();
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
        // After a right password: an old bcrypt hash is replaced with an Argon2id one.
        provider.setUserDetailsPasswordService(passwordUpgrade);

        return provider;
    }

    /**
     * What the password check needs, for that check only. Not a UserDetailsService bean:
     * after login, requests are authenticated by JwtAuthFilter (with a UserPrincipal).
     */
    private LoginDetails loginDetails(String email) {
        return userRepository.findByEmail(email)
                .map(LoginDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
