package com.authcore.auth.config;

import org.springframework.security.core.userdetails.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.authcore.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@EnableAsync
@RequiredArgsConstructor
public class ApplicationConfig {
    public static final String EMAIL_EXECUTOR = "emailExecutor";
    static final int EMAIL_QUEUE_CAPACITY = 500;

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

    /** Sends the emails. Its threads are named email-1 and email-2. */
    @Bean(EMAIL_EXECUTOR)
    ThreadPoolTaskExecutor emailExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(EMAIL_QUEUE_CAPACITY);
        executor.setThreadNamePrefix("email-");
        // On shutdown, first send what is already queued.
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(30);
        // When the queue is full, drop the email. The default throws in the middle of the
        // request, and only requests that really send an email would fail: that shows
        // which accounts exist (H2).
        executor.setRejectedExecutionHandler((task, pool) -> log.error("The email queue is full; an email was dropped"));
        return executor;
    }
}
