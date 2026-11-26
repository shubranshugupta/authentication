package com.authcore.auth.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.authcore.auth.audit.AuditEvent;
import com.authcore.auth.audit.AuditLog;
import com.authcore.auth.ratelimit.LoginThrottle;
import com.authcore.auth.ratelimit.TooManyRequestsException;
import com.authcore.auth.user.User;
import com.authcore.auth.user.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * Checks the password again before an action that a stolen access token mustn't be enough
 * for, such as an admin promoting a user. Wrong passwords count like wrong passwords at
 * login (H9), so a stolen token can't be used to guess the password either.
 */
@Component
@RequiredArgsConstructor
public class Reauthentication {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginThrottle loginThrottle;
    private final AuditLog audit;

    /**
     * @throws WrongPasswordException if the password is wrong
     * @throws com.authcore.auth.ratelimit.TooManyRequestsException if there were too many wrong passwords
     */
    public void check(PasswordConfirmation confirmation) {
        // The access token was checked a moment ago, so the user exists, unless they were just deleted.
        User user = userRepository.findById(confirmation.userId()).orElseThrow(WrongPasswordException::new);
        try {
            loginThrottle.beforeCheck(user.getEmail(), confirmation.ip());
        } catch (TooManyRequestsException e) {
            audit.record(AuditEvent.PASSWORD_CONFIRMATION_FAILED, user.getId(), "reason", "RATE_LIMITED");
            throw e;
        }
        if (!passwordEncoder.matches(confirmation.password(), user.getPassword())) {
            audit.record(AuditEvent.PASSWORD_CONFIRMATION_FAILED, user.getId(), "reason", "WRONG_PASSWORD");
            throw new WrongPasswordException();
        }
        loginThrottle.succeeded(user.getEmail(), confirmation.ip());
    }
}
