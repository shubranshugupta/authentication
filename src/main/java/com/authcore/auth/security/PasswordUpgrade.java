package com.authcore.auth.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.stereotype.Component;

import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Replaces an old (bcrypt) hash with a new (Argon2id) one after a login with the right
 * password, the only time the password itself is known (see {@link PasswordHashing}).
 *
 * <p>Only the hash changes: it's the same password, so sessions and access tokens stay
 * (the token version isn't raised). If the password changed since it was checked, the new
 * one is kept. A failure here only means the old hash stays; the login goes on.
 */
@Slf4j
@Component
@RequiredArgsConstructor
class PasswordUpgrade implements UserDetailsPasswordService {
    private final UserRepository userRepository;
    private final RetryingTransaction transaction;

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        LoginDetails login = (LoginDetails) user;
        try {
            transaction.run(() -> userRepository.findAndLockById(login.getId())
                    // Changed or reset since the check: that one wins.
                    .filter(found -> found.getPassword().equals(login.getPassword()))
                    .map(found -> {
                        found.setPassword(newPassword);
                        return userRepository.save(found);
                    }));
        } catch (RuntimeException e) {
            log.warn("The password hash of user {} could not be upgraded", login.getId(), e);
        }
        return user;
    }
}
