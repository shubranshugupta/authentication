package com.authcore.auth.security;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * At startup: once no bcrypt hashes are left, password checks stop paying for the extra
 * check that keeps their timing equal (PasswordHashing.EqualTiming). New hashes are always
 * Argon2id, so none can come back until the next start.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class PasswordHashMigration {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @EventListener(ApplicationReadyEvent.class)
    void checkForOldHashes() {
        if (!(passwordEncoder instanceof PasswordHashing.Bounded encoder))
            return;
        if (userRepository.anyOldPasswordHashes()) {
            log.info("Some password hashes are still bcrypt: they're replaced at each user's next login");
            return;
        }
        encoder.stopEqualTiming();
    }
}
