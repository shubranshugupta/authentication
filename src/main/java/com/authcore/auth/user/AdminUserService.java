package com.authcore.auth.user;

import java.time.Instant;
import java.util.function.Consumer;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.authcore.auth.common.AuthConfigProperties;
import com.authcore.auth.common.RetryingTransaction;
import com.authcore.auth.security.PasswordConfirmation;
import com.authcore.auth.security.Reauthentication;
import com.authcore.auth.session.SessionService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * What admins can do with other users. Admins can't lock or demote themselves, so nobody
 * locks themselves out by mistake. Every change needs the admin's password.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminUserService {
    public static final int DEFAULT_PAGE_SIZE = 20;
    public static final int MAX_PAGE_SIZE = 100;

    private final UserRepository userRepository;
    private final SessionService sessions;
    private final RetryingTransaction transaction;
    private final AuthConfigProperties properties;
    private final Reauthentication reauthentication;

    /** Users ordered by id. Out-of-range page numbers and sizes are clamped. */
    public AdminUserPageResponse listUsers(int page, int size) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.clamp(size, 1, MAX_PAGE_SIZE);
        Page<User> users = userRepository.findAll(PageRequest.of(safePage, safeSize, Sort.by("id")));

        return new AdminUserPageResponse(
                users.map(AdminUserResponse::from).getContent(),
                users.getNumber(),
                users.getSize(),
                users.getTotalElements(),
                users.getTotalPages());
    }

    public AdminUserResponse getUser(int id) {
        return userRepository.findById(id)
                .map(AdminUserResponse::from)
                .orElseThrow(() -> new UserNotFoundException(id));
    }

    /** Logs the user out everywhere, and keeps them out until they are unlocked. */
    public AdminUserResponse lock(PasswordConfirmation admin, Integer id) {
        reauthentication.check(admin);
        refuseSelf(admin.userId(), id);
        AdminUserResponse user = change(id, found -> {
            if (!found.isLocked())
                found.setLockedAt(Instant.now());
            sessions.endAll(found);
        });
        log.info("Admin {} locked user {}", admin.userId(), id);
        return user;
    }

    public AdminUserResponse unlock(PasswordConfirmation admin, Integer id) {
        reauthentication.check(admin);
        AdminUserResponse user = change(id, found -> found.setLockedAt(null));
        log.info("Admin {} unlocked user {}", admin.userId(), id);
        return user;
    }

    public void endSessions(PasswordConfirmation admin, Integer id) {
        reauthentication.check(admin);
        change(id, sessions::endAll);
        log.info("Admin {} logged user {} out of all devices", admin.userId(), id);
    }

    /** Takes effect with the user's next request: roles are never read from tokens. */
    public AdminUserResponse changeRole(PasswordConfirmation admin, Integer id, Role role) {
        reauthentication.check(admin);
        refuseSelf(admin.userId(), id);
        AdminUserResponse user = change(id, found -> {
            if (role != Role.ADMIN && properties.isAdminEmail(found.getEmail()))
                throw new AdminActionRefusedException(
                        "This email is listed in AUTH_ADMIN_EMAILS, so the next start would make the user an admin again. Remove it there first.");
            found.setRole(role);
        });
        log.info("Admin {} gave the {} role to user {}", admin.userId(), role, id);
        return user;
    }

    private AdminUserResponse change(Integer id, Consumer<User> change) {
        return transaction.run(() -> {
            User user = userRepository.findAndLockById(id).orElseThrow(() -> new UserNotFoundException(id));
            change.accept(user);
            return AdminUserResponse.from(userRepository.save(user));
        });
    }

    private static void refuseSelf(Integer adminId, Integer id) {
        if (adminId.equals(id))
            throw new AdminActionRefusedException("Admins can't do this to themselves.");
    }
}
