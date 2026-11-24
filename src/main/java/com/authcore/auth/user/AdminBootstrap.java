package com.authcore.auth.user;

import java.util.Collection;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.EmailAddresses;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Gives the ADMIN role to existing users listed in auth.admin-emails, at startup.
 * (Users who register later with a listed email get ADMIN at registration.)
 * It only promotes: removing an email from the list doesn't demote anyone.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminBootstrap {
    private final AuthConfigProperties authConfigProperties;
    private final UserRepository userRepository;

    @EventListener(ApplicationReadyEvent.class)
    public void promoteConfiguredAdmins() {
        promote(authConfigProperties.getAdminEmails());
    }

    /** Promotes the existing users with these emails; unknown emails are ignored. */
    public void promote(Collection<String> emails) {
        for (String email : emails) {
            if (email == null || email.isBlank())
                continue;
            userRepository.findByEmail(EmailAddresses.normalize(email)).ifPresent(this::promote);
        }
    }

    private void promote(User user) {
        if (user.getRole() == Role.ADMIN)
            return;
        user.setRole(Role.ADMIN);
        userRepository.save(user);
        log.info("Gave the ADMIN role to user {} (listed in auth.admin-emails)", user.getId());
    }
}
